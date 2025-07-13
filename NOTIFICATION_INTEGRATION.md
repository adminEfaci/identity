# Notification Integration - Identity Module

## Overview

This document describes the notification integration implemented in the Identity module. The system provides comprehensive notification capabilities for user lifecycle events through multiple delivery channels.

## Folder Structure

```
src/
├── infrastructure/
│   ├── notifications/               # 🆕 Notification Infrastructure
│   │   ├── __init__.py             # Public API exports
│   │   ├── config.py               # Configuration settings
│   │   ├── events.py               # Notification event definitions
│   │   ├── handlers.py             # Channel-specific handlers
│   │   ├── processors.py           # Event processing logic
│   │   └── service.py              # High-level notification service
│   │
│   └── messaging.py                # ✅ Enhanced with notification tasks
│
├── application/
│   └── services/
│       └── user_service.py         # ✅ Enhanced with notification emission
│
└── domain/
    └── events.py                   # ✅ Domain events (used by notifications)
```

## Notification System Components

### 1. Configuration (`config.py`)
- **Purpose**: Centralized configuration for notification system
- **Features**:
  - Channel enablement (Email, Slack, Webhook)
  - Retry policies and timeouts
  - Template settings
  - Rate limiting configuration
  - Admin notification settings

### 2. Events (`events.py`)
- **Purpose**: Notification event definitions
- **Event Types**:
  - `UserCreatedNotification`
  - `UserModifiedNotification`
  - `UserDeletedNotification`
  - `UserPasswordChangedNotification`
  - `UserRoleAssignedNotification`
  - `UserRoleRemovedNotification`
  - `UserStatusChangedNotification`

### 3. Handlers (`handlers.py`)
- **Purpose**: Channel-specific delivery implementations
- **Handlers**:
  - `EmailNotificationHandler` - SMTP email delivery
  - `SlackNotificationHandler` - Slack webhook integration
  - `WebhookNotificationHandler` - Custom webhook delivery

### 4. Processors (`processors.py`)
- **Purpose**: Event routing and processing coordination
- **Features**:
  - Handler selection based on channels
  - Batch processing capabilities
  - Error handling and retry logic

### 5. Service (`service.py`)
- **Purpose**: High-level notification orchestration
- **Features**:
  - Domain event to notification conversion
  - Notification creation and dispatch
  - Integration with message bus

## Message Bus Integration

The messaging system has been enhanced with notification-specific Celery tasks:

### New Tasks
- `identity.notifications.process_notification_event`
- `identity.notifications.send_user_welcome_email`
- `identity.notifications.send_password_change_alert`
- `identity.notifications.batch_process_notifications`

### Convenience Methods
```python
# Send notification event
await message_bus.publish_notification_event(notification_data)

# Send welcome email
await message_bus.send_user_welcome_email(
    user_id, email, first_name, last_name, username
)

# Send password change alert
await message_bus.send_password_change_alert(
    user_id, email, first_name, last_name, changed_by, is_self_change
)

# Batch process notifications
await message_bus.batch_process_notifications(notification_batch)
```

## UserService Integration

The UserService has been enhanced to emit notifications alongside domain events:

### Enhanced Methods
- `create_user()` - Emits `UserCreatedNotification`
- `modify_user()` - Emits `UserModifiedNotification`
- `delete_user()` - Emits `UserDeletedNotification`
- `change_password()` - Emits `UserPasswordChangedNotification`
- `assign_role()` - Emits `UserRoleAssignedNotification`
- `remove_role()` - Emits `UserRoleRemovedNotification`
- `change_status()` - Emits `UserStatusChangedNotification`

### Dependency Injection
```python
user_service = UserService(
    user_repository=user_repo,
    domain_service=domain_service,
    message_bus=message_bus,
    notification_service=notification_service  # 🆕 Added dependency
)
```

## Usage Examples

### 1. Basic Notification Creation
```python
from src.infrastructure.notifications import (
    UserCreatedNotification,
    NotificationChannel,
    NotificationPriority
)

notification = UserCreatedNotification(
    event_id=event.event_id,
    user_id=user.id,
    occurred_at=datetime.utcnow(),
    email=user.email,
    first_name=user.first_name,
    last_name=user.last_name,
    username=user.username,
    channels=frozenset([NotificationChannel.EMAIL, NotificationChannel.SLACK]),
    priority=NotificationPriority.NORMAL
)
```

### 2. Service Configuration
```python
from src.infrastructure.notifications import NotificationConfig

config = NotificationConfig(
    enabled=True,
    email_enabled=True,
    slack_enabled=True,
    webhook_enabled=False,
    max_retry_attempts=3,
    retry_delay_seconds=30
)
```

### 3. Handler Usage
```python
from src.infrastructure.notifications import EmailNotificationHandler

handler = EmailNotificationHandler(config)
success = await handler.send_notification(notification)
```

## Event Flow

1. **Domain Event Occurs** (e.g., UserCreated)
2. **UserService emits notification** via NotificationService
3. **NotificationService creates** appropriate notification event
4. **Message Bus publishes** notification to Celery queue
5. **Celery Worker processes** notification asynchronously
6. **Handlers deliver** notification through configured channels

## Configuration Options

### Email Configuration
```python
email_enabled=True
email_from_address="noreply@identity.local"
smtp_host="smtp.example.com"
smtp_port=587
smtp_use_tls=True
```

### Slack Configuration
```python
slack_enabled=True
slack_webhook_url="https://hooks.slack.com/services/..."
slack_default_channel="#notifications"
slack_bot_name="Identity Bot"
```

### Webhook Configuration
```python
webhook_enabled=True
webhook_urls=["https://api.external.com/webhooks/identity"]
webhook_timeout_seconds=30
webhook_include_sensitive_data=False
```

## Error Handling

- **Retry Logic**: Exponential backoff with configurable attempts
- **Dead Letter Queues**: Failed notifications moved to DLQ
- **Graceful Degradation**: System continues if notifications fail
- **Logging**: Comprehensive error logging and monitoring

## Security Considerations

- **Sensitive Data**: Optional masking in webhook payloads
- **Authentication**: SMTP and webhook authentication support
- **Rate Limiting**: Per-user notification limits
- **Audit Trail**: All notifications logged for audit purposes

## Testing

The notification system includes comprehensive test coverage:
- Unit tests for handlers and processors
- Integration tests with message bus
- Mock implementations for external services

## Future Enhancements

Potential future improvements:
- SMS notification handler
- Push notification support
- Template engine integration
- Advanced filtering and preferences
- Notification analytics and metrics

---

**Note**: This notification system is designed to be highly configurable, scalable, and maintainable while following Domain-Driven Design principles.