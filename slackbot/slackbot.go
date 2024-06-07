package slackbot

import (
	"fmt"

	"github.com/slack-go/slack"
)

type Bot struct {
	client  *slack.Client
	channel string
}

func New(token, channel string) (*Bot, error) {
	bot := &Bot{
		client:  slack.New(token, slack.OptionDebug(false)),
		channel: channel,
	}
	// check that the bot is connected to the slack API
	_, err := bot.client.AuthTest()
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with slack: %v", err)
	}
	return bot, nil
}

func (b *Bot) Say(message string) error {
	fmt.Println("Message:", message)
	fmt.Println("Slack disabled")
	return nil
	_, _, err := b.client.PostMessage(b.channel, slack.MsgOptionText(message, false))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	return nil
}
