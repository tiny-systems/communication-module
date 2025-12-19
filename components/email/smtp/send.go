package smtp

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/tiny-systems/module/module"
	"github.com/tiny-systems/module/registry"
	"github.com/wneessen/go-mail"
)

const (
	ComponentName = "smtp_send_email"
	ResponsePort  = "response"
	ErrorPort     = "error"
	RequestPort   = "request"
)

type Settings struct {
	EnableErrorPort    bool `json:"enableErrorPort" required:"true" title:"Enable Error Port" description:"If error happen during mail send, error port will emit an error message"`
	EnableResponsePort bool `json:"enableResponsePort" required:"true" title:"Enable Response port"`
}

type Recipient struct {
	Name  string `json:"name" title:"Name" colSpan:"col-span-6"`
	Email string `json:"email" required:"true" title:"Email settings" format:"email" minLength:"1" colSpan:"col-span-6"`
}

type Context any

type Request struct {
	Context      Context      `json:"context,omitempty" configurable:"true" title:"Context"`
	SmtpSettings SmtpSettings `json:"smtpSettings" required:"true" title:"SMTP Settings"`

	ContentType string `json:"contentType" required:"true" title:"Content type" enum:"text/plain,text/html,application/octet-stream"`

	From string      `json:"from" title:"From"`
	To   []Recipient `json:"to" required:"true" description:"List of recipients" title:"To" uniqueItems:"true" minItems:"1"`

	Subject string `json:"subject" title:"Subject"`
	Body    string `json:"body" title:"Email body" format:"textarea"`
}

type SmtpSettings struct {
	Host     string `json:"host" required:"true" minLength:"1" title:"SMTP Host"`
	Port     int    `json:"port" required:"true" title:"SMTP Port"`
	Username string `json:"username" title:"SMTP username" required:"true"`
	Password string `json:"password" title:"SMTP password" required:"true"`
	Test     bool   `json:"test" format:"button" title:"Test connection" required:"true"`
}

type Response struct {
	Context   Context `json:"context"`
	MessageID string  `json:"messageID"`
}

type Error struct {
	Context   Context `json:"context"`
	Error     string  `json:"error"`
	MessageID string  `json:"messageID"`
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
		Description: "SMTP Email Sender",
		Info:        "Sends email using SMTP protocol",
		Tags:        []string{"Email", "SMTP"},
	}
}
func (t *Component) send(ctx context.Context, sendMsg Request) (string, error) {

	messageID, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	client, err := mail.NewClient(sendMsg.SmtpSettings.Host, mail.WithPort(sendMsg.SmtpSettings.Port), mail.WithSMTPAuth(mail.SMTPAuthLogin),
		mail.WithUsername(sendMsg.SmtpSettings.Username), mail.WithPassword(sendMsg.SmtpSettings.Password))

	if err != nil {
		return "", err
	}

	err = client.DialWithContext(ctx)
	if err != nil {
		return "", err
	}

	m := mail.NewMsg()
	_ = m.From(sendMsg.From)
	for _, t := range sendMsg.To {
		_ = m.To(fmt.Sprintf("%s <%s>", t.Name, t.Email))
	}

	m.Subject(sendMsg.Subject)
	m.SetBodyString(mail.ContentType(sendMsg.ContentType), sendMsg.Body)

	defer func() {
		_ = client.Close()
	}()

	err = client.Send(m)
	if err != nil {
		return "", err
	}

	return messageID.String(), nil
}

func (t *Component) Handle(ctx context.Context, responseHandler module.Handler, port string, msg interface{}) error {
	if port == module.SettingsPort {
		in, ok := msg.(Settings)
		if !ok {
			return fmt.Errorf("invalid settings")
		}
		t.settings = in
		return nil
	}

	if port != RequestPort {
		return fmt.Errorf("unknown port %s", port)
	}

	sendMsg, ok := msg.(Request)
	if !ok {
		return fmt.Errorf("invalid message")
	}

	messageID, err := t.send(ctx, sendMsg)
	if err != nil {
		if !t.settings.EnableErrorPort {
			return err
		}
		return responseHandler(ctx, ErrorPort, Error{
			Context:   sendMsg.Context,
			Error:     err.Error(),
			MessageID: messageID,
		})
	}

	if t.settings.EnableResponsePort {
		return responseHandler(ctx, ResponsePort, Response{
			Context:   sendMsg.Context,
			MessageID: messageID,
		})
	}
	// send email here
	return err
}

func (t *Component) Ports() []module.Port {
	ports := []module.Port{
		{
			Name:          module.SettingsPort,
			Label:         "Settings",
			Configuration: Settings{},
		},
		{
			Name:  RequestPort,
			Label: "Request",
			Configuration: Request{
				Body:        "Email text",
				ContentType: "text/html",
				SmtpSettings: SmtpSettings{
					Host: "smtp.domain.com",
					Port: 587,
				},
				To: []Recipient{
					{
						Name:  "John Doe",
						Email: "johndoe@example.com",
					},
				},
			},
			Position: module.Left,
		},
	}
	if t.settings.EnableResponsePort {
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
		Name:          ErrorPort,
		Label:         "Error",
		Source:        true,
		Configuration: Error{},
	})
}

var _ module.Component = (*Component)(nil)

func init() {
	registry.Register(&Component{})
}
