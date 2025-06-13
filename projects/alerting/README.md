# Alerting Service

A microservice for the Nemesis platform that handles alert notifications through various channels using the [Apprise](https://github.com/caronc/apprise) library.

## Purpose

This service processes alert events from the Nemesis platform and delivers notifications to configured external services like Slack, Discord, email, webhooks, and other notification platforms supported by Apprise.

## Features

- Multi-channel notification support via Apprise
- Rate limiting with configurable concurrent alert processing
- Automatic retry logic with exponential backoff
- Real-time feedback subscription from Hasura GraphQL
- Support for tagged notifications to specific channels
- Health monitoring and test endpoints

## Configuration

The service is configured using environment variables:

- `APPRISE_URLS`: Comma-separated list of Apprise notification URLs with optional tags
- `MAX_CONCURRENT_ALERTS`: Maximum number of concurrent alert processing (default: 10)
- `MAX_ALERT_RETRIES`: Number of retry attempts for failed alerts (default: 5)
- `RETRY_DELAY_SECONDS`: Delay between retry attempts (default: 30)
- `NEMESIS_URL`: Base URL of the Nemesis installation (default: http://localhost/)

## Alert Sources

The service handles alerts from two sources:

1. **Direct alerts**: Published to the `alert` topic via Dapr pub/sub
2. **Feedback alerts**: Automatically generated from user feedback in the files_feedback table

## Endpoints

- `GET /healthz`: Health check endpoint for Docker healthcheck
- `POST /test/alert`: Test endpoint for sending sample alerts

## Notification Channels

Supports all Apprise-compatible services including:
- Slack
- Discord
- Microsoft Teams
- Email (SMTP)
- Webhooks
- And many more...

