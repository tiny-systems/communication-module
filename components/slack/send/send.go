package send

import (
	"context"
	"fmt"

	"github.com/slack-go/slack"
	"github.com/tiny-systems/module/api/v1alpha1"
	"github.com/tiny-systems/module/module"
	"github.com/tiny-systems/module/registry"
)

const (
	ComponentName = "send_slack_channel"
	ResponsePort  = "response"
	ErrorPort     = "error"
	RequestPort   = "request"
)

type Settings struct {
	EnableSuccessPort bool `json:"enableSuccessPort" required:"true" title:"Enable Success port" description:""`
	EnableErrorPort   bool `json:"enableErrorPort" required:"true" title:"Enable Error Port" description:"If error happen during send, error port will emit an error message"`
}

type Context any

type Message struct {
	ChannelID  string `json:"channelID" required:"true" minLength:"1" title:"ChannelID" description:""`
	SlackToken string `json:"slackToken" required:"true" minLength:"1" title:"Slack token" description:"Bot User OAuth Token"`
	Text       string `json:"text" required:"true" minLength:"1" title:"Message text" format:"textarea"`
}

type Request struct {
	Context Context `json:"context,omitempty" configurable:"true" title:"Context"`
	Message Message `json:"slack_message" required:"true" title:"Slack Message"`
}

type Response struct {
	Request Request `json:"request"`
	Sent    Message `json:"sent"`
}

type Error struct {
	Context Context `json:"context"`
	Error   string  `json:"error"`
}

type Component struct {
	settings Settings
}

func (t *Component) Instance() module.Component {
	return &Component{
		settings: Settings{},
	}
}

func (t *Component) GetInfo() module.ComponentInfo {
	return module.ComponentInfo{
		Name:        ComponentName,
		Description: "Slack Channel Sender",
		Info:        "Sends messages to slack channel",
		Tags:        []string{"Slack", "IM"},
	}
}

func (t *Component) Handle(ctx context.Context, responseHandler module.Handler, port string, msg interface{}) any {
	if port == v1alpha1.SettingsPort {
		in, ok := msg.(Settings)
		if !ok {
			return fmt.Errorf("invalid settings")
		}
		t.settings = in
		return nil
	}

	in, ok := msg.(Request)
	if !ok {
		return fmt.Errorf("invalid message")
	}

	client := slack.New(in.Message.SlackToken)
	_, _, _, err := client.SendMessageContext(ctx, in.Message.ChannelID, slack.MsgOptionText(in.Message.Text, true))

	if err != nil {
		if !t.settings.EnableErrorPort {
			return err
		}
		return responseHandler(ctx, ErrorPort, Error{
			Context: in.Context,
			Error:   err.Error(),
		})
	}

	if t.settings.EnableSuccessPort {
		return responseHandler(ctx, ResponsePort, Response{
			Request: in,
			Sent:    in.Message,
		})
	}
	// send email here
	return err
}

func (t *Component) Ports() []module.Port {
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
				Message: Message{
					Text: "Message to send",
				},
			},
			Position: module.Left,
		},
	}
	if t.settings.EnableSuccessPort {
		ports = append(ports, module.Port{
			Position:      module.Right,
			Name:          ResponsePort,
			Label:         "Response",
			Source:        true,
			Configuration: Response{},
		})
	}

	if !t.settings.EnableErrorPort {
		return ports
	}
	return append(ports, module.Port{
		Position:      module.Bottom,
		Name:          ResponsePort,
		Label:         "Error",
		Source:        true,
		Configuration: Error{},
	})
}

var _ module.Component = (*Component)(nil)

func init() {
	registry.Register(&Component{})
}
