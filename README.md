# 📦 Prisma Database Schema Review — Messenger App

This schema powers a fully featured messenger app built with scalability and maintainability in mind. It supports users, real-time messaging, group conversations, media attachments, reactions, logging, and more.

---

## 🧑‍💼 User

A user can register using either an email or phone number. Every user must have a username and password. Optional fields include first name, last name, and description, allowing for a more personalized profile.

Users have roles that define their permissions in the system. They can live in different timezones, may be banned, and their last activity is recorded. Users may have a profile image. They can join conversations, send and forward messages, reply to others, react with emojis, and see who has read a message. All significant user actions are recorded.

---

## 💬 Conversation

Conversations can either be private chats between two users or group chats with multiple participants. Group chats can have a name, description, and icon, and can be archived. Each conversation includes messages and members.

---

## 👥 ConversationMember

This links a user to a conversation and stores their role, such as MEMBER, ADMIN, or OWNER. It also records when the user joined the conversation. A user cannot be added to the same conversation more than once.

---

## ✉️ Message

Messages belong to a conversation and are sent by users. They can be plain text, images, video, or audio. Messages support replying and forwarding. A message can be deleted, edited, or pinned. If forwarded, the system stores details of the original sender and time. Users can react to messages or mark them as seen. Previous versions of edited messages are stored.

---

## 📁 MessageEditHistory

Keeps past versions of messages so users or admins can review what was changed and when.

---

## 😊 MessageReaction

Lets users respond to messages with emoji. A user can only react once to a given message.

---

## 👁️ MessageSeen

Records which users have seen which messages and when they saw them.

---

## 💾 ActionLog

Tracks major user actions like editing or deleting content. Useful for audits and analytics.

---

## 🗂️ Media

Handles uploaded content like images, videos, or audio. Files are stored via their URL and linked to users, messages, or conversations. Each file has metadata like type, size, and MIME type.

---

## 🔠 Enum Definitions

### ConversationType

Defines whether a conversation is private or a group.

* ONE\_TO\_ONE
* GROUP

### MessageContentType

Defines what kind of content a message has.

* MESSAGE\_TEXT
* MESSAGE\_IMAGE
* MESSAGE\_VIDEO
* MESSAGE\_AUDIO

### ConversationRole

Defines what a participant can do in a conversation.

* MEMBER
* ADMIN
* OWNER

### UserRole

Defines a user's level in the system.

* USER
* MODERATOR
* ANALYTICS
* ADMIN
* CREATOR

### StoredMediaType

Defines the type of media uploaded.

* MEDIA\_IMAGE
* MEDIA\_VIDEO
* MEDIA\_AUDIO
* MEDIA\_DOCUMENT
* MEDIA\_OTHER
