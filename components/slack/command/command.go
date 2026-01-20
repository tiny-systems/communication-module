package command

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tiny-systems/module/api/v1alpha1"
	"github.com/tiny-systems/module/module"
	"github.com/tiny-systems/module/registry"
)

const (
	ComponentName = "slack_command"
	CommandPort   = "command"
	ErrorPort     = "error"
	RequestPort   = "request"
)

// Settings configures the component
type Settings struct {
	SigningSecret   string `json:"signingSecret" required:"true" title:"Signing Secret" description:"Slack app signing secret for request verification" format:"password"`
	EnableErrorPort bool   `json:"enableErrorPort" title:"Enable Error Port" description:"Output errors to error port instead of failing"`
	SkipVerify      bool   `json:"skipVerify" title:"Skip Verification" description:"Skip signature verification (for testing only)"`
}

// Request is the incoming HTTP request from Slack
type Request struct {
	// HTTP headers needed for verification
	Headers map[string]string `json:"headers" title:"Headers" description:"HTTP headers from the request"`
	// Raw body for signature verification
	Body string `json:"body" required:"true" title:"Body" description:"Raw request body"`
}

// Command is the parsed slash command
type Command struct {
	// Original request context
	ResponseURL string `json:"responseUrl" title:"Response URL" description:"URL to send delayed responses"`
	TriggerID   string `json:"triggerId" title:"Trigger ID" description:"ID for opening modals"`

	// Command details
	Command     string `json:"command" title:"Command" description:"The slash command used (e.g., /deploy)"`
	Text        string `json:"text" title:"Text" description:"Text after the command"`
	Args        []string `json:"args" title:"Args" description:"Text split into arguments"`

	// User info
	UserID   string `json:"userId" title:"User ID" description:"Slack user ID"`
	UserName string `json:"userName" title:"User Name" description:"Slack username"`

	// Channel info
	ChannelID   string `json:"channelId" title:"Channel ID" description:"Channel where command was invoked"`
	ChannelName string `json:"channelName" title:"Channel Name" description:"Channel name"`

	// Team info
	TeamID     string `json:"teamId" title:"Team ID" description:"Slack workspace ID"`
	TeamDomain string `json:"teamDomain" title:"Team Domain" description:"Slack workspace domain"`

	// For routing
	Action    string `json:"action" title:"Action" description:"First argument (e.g., 'status' from '/k8s status app')"`
	Target    string `json:"target" title:"Target" description:"Second argument (e.g., 'app' from '/k8s status app')"`
	ExtraArgs []string `json:"extraArgs" title:"Extra Args" description:"Remaining arguments after action and target"`
}

// Error output
type Error struct {
	Error   string  `json:"error" title:"Error"`
	Request Request `json:"request" title:"Request"`
}

// Component implements the Slack command receiver
type Component struct {
	settings Settings
}

func (c *Component) Instance() module.Component {
	return &Component{}
}

func (c *Component) GetInfo() module.ComponentInfo {
	return module.ComponentInfo{
		Name:        ComponentName,
		Description: "Slack Command",
		Info:        "Receives and parses Slack slash commands. Connect to HTTP Server to receive webhooks. Verifies request signature and outputs parsed command for routing.",
		Tags:        []string{"Slack", "ChatOps", "Webhook"},
	}
}

func (c *Component) Handle(ctx context.Context, handler module.Handler, port string, msg any) any {
	switch port {
	case v1alpha1.SettingsPort:
		in, ok := msg.(Settings)
		if !ok {
			return fmt.Errorf("invalid settings")
		}
		c.settings = in
		return nil

	case RequestPort:
		in, ok := msg.(Request)
		if !ok {
			return fmt.Errorf("invalid request")
		}
		return c.handleRequest(ctx, handler, in)
	}

	return fmt.Errorf("unknown port: %s", port)
}

func (c *Component) handleRequest(ctx context.Context, handler module.Handler, req Request) error {
	// Verify signature unless skipped
	if !c.settings.SkipVerify {
		if err := c.verifySignature(req); err != nil {
			return c.handleError(ctx, handler, req, fmt.Sprintf("signature verification failed: %v", err))
		}
	}

	// Parse the command
	cmd, err := c.parseCommand(req.Body)
	if err != nil {
		return c.handleError(ctx, handler, req, fmt.Sprintf("failed to parse command: %v", err))
	}

	// Emit the parsed command
	if result := handler(ctx, CommandPort, cmd); result != nil {
		if err, ok := result.(error); ok {
			return err
		}
	}
	return nil
}

func (c *Component) verifySignature(req Request) error {
	if c.settings.SigningSecret == "" {
		return fmt.Errorf("signing secret not configured")
	}

	// Get headers (case-insensitive)
	timestamp := ""
	signature := ""
	for k, v := range req.Headers {
		lower := strings.ToLower(k)
		if lower == "x-slack-request-timestamp" {
			timestamp = v
		} else if lower == "x-slack-signature" {
			signature = v
		}
	}

	if timestamp == "" || signature == "" {
		return fmt.Errorf("missing Slack signature headers")
	}

	// Check timestamp to prevent replay attacks (5 minute window)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if abs(time.Now().Unix()-ts) > 300 {
		return fmt.Errorf("timestamp too old")
	}

	// Compute expected signature
	sigBaseString := fmt.Sprintf("v0:%s:%s", timestamp, req.Body)
	mac := hmac.New(sha256.New, []byte(c.settings.SigningSecret))
	mac.Write([]byte(sigBaseString))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

func (c *Component) parseCommand(body string) (Command, error) {
	// Parse URL-encoded form data
	params := make(map[string]string)
	for _, pair := range strings.Split(body, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := urlDecode(parts[1])
			params[key] = value
		}
	}

	text := params["text"]
	args := parseArgs(text)

	cmd := Command{
		ResponseURL: params["response_url"],
		TriggerID:   params["trigger_id"],
		Command:     params["command"],
		Text:        text,
		Args:        args,
		UserID:      params["user_id"],
		UserName:    params["user_name"],
		ChannelID:   params["channel_id"],
		ChannelName: params["channel_name"],
		TeamID:      params["team_id"],
		TeamDomain:  params["team_domain"],
	}

	// Extract action and target for easy routing
	if len(args) > 0 {
		cmd.Action = args[0]
	}
	if len(args) > 1 {
		cmd.Target = args[1]
	}
	if len(args) > 2 {
		cmd.ExtraArgs = args[2:]
	}

	return cmd, nil
}

func (c *Component) handleError(ctx context.Context, handler module.Handler, req Request, errMsg string) error {
	if c.settings.EnableErrorPort {
		_ = handler(ctx, ErrorPort, Error{
			Error:   errMsg,
			Request: req,
		})
		return nil
	}
	return errors.New(errMsg)
}

func (c *Component) Ports() []module.Port {
	ports := []module.Port{
		{
			Name:          v1alpha1.SettingsPort,
			Label:         "Settings",
			Configuration: Settings{},
		},
		{
			Name:  RequestPort,
			Label: "Request",
			Configuration: Request{
				Headers: map[string]string{
					"X-Slack-Request-Timestamp": "1234567890",
					"X-Slack-Signature":         "v0=...",
				},
				Body: "command=/k8s&text=status+myapp&user_id=U123&channel_id=C456",
			},
			Position: module.Left,
		},
		{
			Name:   CommandPort,
			Label:  "Command",
			Source: true,
			Configuration: Command{
				Command: "/k8s",
				Action:  "status",
				Target:  "myapp",
			},
			Position: module.Right,
		},
	}

	if c.settings.EnableErrorPort {
		ports = append(ports, module.Port{
			Name:          ErrorPort,
			Label:         "Error",
			Source:        true,
			Configuration: Error{},
			Position:      module.Bottom,
		})
	}

	return ports
}

// Helper functions

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func urlDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				result = append(result, b...)
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result)
}

func parseArgs(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	return strings.Fields(text)
}

var _ module.Component = (*Component)(nil)

func init() {
	registry.Register(&Component{})
}
