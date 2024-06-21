package slackbot

import (
	"fmt"
	"log/slog"

	"github.com/slack-go/slack"
)

type Bot struct {
	client  *slack.Client
	channel string
	logger  *slog.Logger
	debug   bool
}

func New(token, channel string, logger *slog.Logger, debug bool) (*Bot, error) {
	bot := &Bot{
		client:  slack.New(token, slack.OptionDebug(false)),
		channel: channel,
		logger:  logger,
		debug:   debug,
	}
	// check that the bot is connected to the slack API
	_, err := bot.client.AuthTest()
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with slack: %v", err)
	}
	logger.Debug("slack auth successful")
	return bot, nil
}

func (b *Bot) Say(message string) error {
	if b.debug {
		b.logger.Debug("debug mode enabled, not posting message to slack", "message", message)
		return nil
	}
	b.logger.Info("Posting message to slack", "message", message)
	_, _, err := b.client.PostMessage(b.channel, slack.MsgOptionText(message, false))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	return nil
}
