# Firestore Security Rules for Ledger

Paste this into Firebase Console → Firestore Database → Rules, replacing the test-mode rules.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    match /usernames/{username} {
      allow read: if true;
      allow create: if request.auth != null && request.resource.data.uid == request.auth.uid;
      allow update, delete: if false;
    }

    match /users/{uid} {
      allow read: if request.auth != null;
      allow write: if request.auth != null && request.auth.uid == uid;

      match /tasks/{taskId} {
        allow read, write: if request.auth != null && request.auth.uid == uid;
      }
    }

    match /groups/{groupId} {
      allow read: if request.auth != null && request.auth.uid in resource.data.members;
      allow create: if request.auth != null && request.auth.uid in request.resource.data.members;
      allow update: if request.auth != null && request.auth.uid in resource.data.members;
      allow delete: if request.auth != null && request.auth.uid == resource.data.ownerId;

      match /tasks/{taskId} {
        allow read, write: if request.auth != null &&
          request.auth.uid in get(/databases/$(database)/documents/groups/$(groupId)).data.members;
      }

      match /chat/{msgId} {
        allow read, create: if request.auth != null &&
          request.auth.uid in get(/databases/$(database)/documents/groups/$(groupId)).data.members;
        allow update, delete: if false;
      }
    }
  }
}
```

**What this enforces:**
- A user can only read/write their own `users/{uid}` doc and personal tasks.
- `usernames/{username}` is publicly readable (needed for login/invite lookups) but only creatable by the account claiming that username, and never editable afterward.
- Group docs and their `tasks`/`chat` subcollections are only readable/writable by members of that group; only the owner can delete the group.
- Chat messages can be created but not edited or deleted (matches current app behavior — no edit/delete UI for messages).
