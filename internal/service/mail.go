package service

import "log/slog"

type MailService struct {
	logger *slog.Logger
}

func NewMailService(logger *slog.Logger) *MailService {
	return &MailService{logger: logger}
}

func (ms *MailService) SendWarningMessage(email string) {
	ms.logger.Info("message send to email", "email", email)
}
