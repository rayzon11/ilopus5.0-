use std::path::PathBuf;

use api::{
    client::AnthropicClient,
    types::{
        ContentBlockDelta, InputContentBlock, InputMessage, MessageRequest, StreamEvent,
        ToolResultContentBlock,
    },
};
use runtime::{
    load_system_prompt, ApiClient, ApiRequest, AssistantEvent, ContentBlock, ConversationMessage,
    ConversationRuntime, MessageRole, PermissionMode, PermissionPolicy, RuntimeFeatureConfig,
    Session, StaticToolExecutor, TokenUsage, TurnSummary,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime as TokioRuntime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTurnRequest {
    pub user_id: String,
    pub session_id: Option<String>,
    pub model: String,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTurnResponse {
    pub session_id: String,
    pub messages: Vec<AgentMessage>,
    pub usage: Option<TokenUsage>,
}

#[derive(Debug)]
pub struct AgentServiceConfig {
    pub cwd: PathBuf,
    pub os_name: String,
    pub os_version: String,
    pub default_model: String,
}

impl Default for AgentServiceConfig {
    fn default() -> Self {
        Self {
            cwd: PathBuf::from("."),
            os_name: std::env::consts::OS.to_string(),
            os_version: "unknown".to_string(),
            default_model: "claude-opus-5-0".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct AgentService {
    config: AgentServiceConfig,
}

impl AgentService {
    pub fn new(config: AgentServiceConfig) -> Self {
        Self { config }
    }

    fn build_system_prompt(&self) -> Result<Vec<String>, runtime::PromptBuildError> {
        let today = chrono::Utc::now().date_naive().to_string();
        load_system_prompt(
            &self.config.cwd,
            today,
            &self.config.os_name,
            &self.config.os_version,
        )
    }

    fn build_permission_policy(&self) -> PermissionPolicy {
        // For SaaS HTTP usage we default to disabling tools for safety.
        PermissionPolicy::from_mode(PermissionMode::ReadOnly)
    }

    pub fn run_turn(
        &self,
        request: AgentTurnRequest,
    ) -> Result<AgentTurnResponse, Box<dyn std::error::Error>> {
        let system_prompt = self.build_system_prompt()?;

        let session = Session::new();

        let api_client = HttpAnthropicClient::from_env(request.model.clone())?;
        let tool_executor = StaticToolExecutor::new();
        let permission_policy = self.build_permission_policy();
        let feature_config = RuntimeFeatureConfig::default();

        let mut runtime = ConversationRuntime::new_with_features(
            session,
            api_client,
            tool_executor,
            permission_policy,
            system_prompt,
            feature_config,
        );

        // Limit iterations for safety in SaaS context.
        runtime = runtime.with_max_iterations(8);

        let summary = runtime.run_turn(request.prompt, None)?;

        Ok(AgentTurnResponse {
            session_id: request
                .session_id
                .unwrap_or_else(|| "session-ephemeral".to_string()),
            messages: flatten_turn_summary(&summary),
            usage: Some(summary.usage),
        })
    }
}

fn flatten_turn_summary(summary: &TurnSummary) -> Vec<AgentMessage> {
    let mut result = Vec::new();
    for msg in &summary.assistant_messages {
        if msg.role == MessageRole::Assistant {
            let text = msg
                .blocks
                .iter()
                .filter_map(|block| match block {
                    runtime::ContentBlock::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !text.is_empty() {
                result.push(AgentMessage {
                    role: "assistant".to_string(),
                    content: text,
                });
            }
        }
    }
    result
}

struct HttpAnthropicClient {
    client: AnthropicClient,
    model: String,
}

impl HttpAnthropicClient {
    fn from_env(model: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = AnthropicClient::from_env()?.with_base_url(api::read_base_url());
        Ok(Self { client, model })
    }
}

impl ApiClient for HttpAnthropicClient {
    fn stream(&mut self, request: ApiRequest) -> Result<Vec<AssistantEvent>, runtime::RuntimeError> {
        let message_request = MessageRequest {
            model: self.model.clone(),
            max_tokens: 64_000,
            messages: convert_messages(&request.messages),
            system: (!request.system_prompt.is_empty()).then(|| request.system_prompt.join("\n\n")),
            tools: None,
            tool_choice: None,
            stream: true,
        };

        // Use the async streaming API and collect into AssistantEvent items.
        let rt = TokioRuntime::new()
            .map_err(|error| runtime::RuntimeError::new(error.to_string()))?;

        rt.block_on(async {
            let mut stream = self
                .client
                .stream_message(&message_request)
                .await
                .map_err(|error| runtime::RuntimeError::new(error.to_string()))?;

            let mut events = Vec::new();
            while let Some(event) = stream
                .next_event()
                .await
                .map_err(|error| runtime::RuntimeError::new(error.to_string()))?
            {
                match event {
                    StreamEvent::ContentBlockDelta(delta) => match delta.delta {
                        ContentBlockDelta::TextDelta { text } => {
                            if !text.is_empty() {
                                events.push(AssistantEvent::TextDelta(text));
                            }
                        }
                        ContentBlockDelta::InputJsonDelta { .. } => {}
                    },
                    StreamEvent::MessageDelta(delta) => {
                        events.push(AssistantEvent::Usage(TokenUsage {
                            input_tokens: delta.usage.input_tokens,
                            output_tokens: delta.usage.output_tokens,
                            cache_creation_input_tokens: 0,
                            cache_read_input_tokens: 0,
                        }));
                    }
                    StreamEvent::MessageStop(_) => events.push(AssistantEvent::MessageStop),
                    _ => {}
                }
            }
            Ok(events)
        })
    }
}

fn convert_messages(messages: &[ConversationMessage]) -> Vec<InputMessage> {
    messages
        .iter()
        .filter_map(|message| {
            let role = match message.role {
                MessageRole::System | MessageRole::User | MessageRole::Tool => "user",
                MessageRole::Assistant => "assistant",
            };
            let content = message
                .blocks
                .iter()
                .map(|block| match block {
                    ContentBlock::Text { text } => InputContentBlock::Text { text: text.clone() },
                    ContentBlock::ToolUse { id, name, input } => InputContentBlock::ToolUse {
                        id: id.clone(),
                        name: name.clone(),
                        input: serde_json::from_str(input)
                            .unwrap_or_else(|_| serde_json::json!({ "raw": input })),
                    },
                    ContentBlock::ToolResult {
                        tool_use_id,
                        output,
                        is_error,
                        ..
                    } => InputContentBlock::ToolResult {
                        tool_use_id: tool_use_id.clone(),
                        content: vec![ToolResultContentBlock::Text {
                            text: output.clone(),
                        }],
                        is_error: *is_error,
                    },
                })
                .collect::<Vec<_>>();
            (!content.is_empty()).then(|| InputMessage {
                role: role.to_string(),
                content,
            })
        })
        .collect()
}

