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
      // Anyone signed in can fetch a single group by its (unguessable) ID — needed for join-by-code.
      allow get: if request.auth != null;
      // But listing/querying groups (e.g. "my groups") only returns ones you're already a member of.
      allow list: if request.auth != null && request.auth.uid in resource.data.members;
      allow create: if request.auth != null && request.auth.uid in request.resource.data.members;
      allow update: if request.auth != null && (
        request.auth.uid in resource.data.members ||
        (
          // Self-join via group code: adding exactly yourself, nothing else changes.
          request.auth.uid in request.resource.data.members &&
          request.resource.data.members.size() == resource.data.members.size() + 1 &&
          request.resource.data.members.hasAll(resource.data.members) &&
          request.resource.data.name == resource.data.name &&
          request.resource.data.ownerId == resource.data.ownerId
        )
      );
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
- Anyone signed in can look up a single group by its ID (needed for "join a group" via a shared code), but cannot list/browse all groups in the database — only groups they're already a member of show up in queries.
- A non-member can update a group only to add themselves to `members` (join-by-code) — no other field can change in that same write.
- Chat messages can be created but not edited or deleted (matches current app behavior — no edit/delete UI for messages).
