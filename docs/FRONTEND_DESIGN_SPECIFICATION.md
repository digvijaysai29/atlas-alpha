# Atlas Front-End Design Specification

## Project Overview

**Atlas** is an agent-first enterprise workspace where a unified AI agent sits at the center and uses applications as tools. The system is built around:

- **Personal Knowledge Graph (PKG)**: Per-user context, history, preferences
- **Organizational Knowledge Graph (OKG)**: Company-wide knowledge with RBAC-scoped access
- **Human-in-the-Loop Approval Gate**: All irreversible actions require explicit human approval
- **Append-Only Audit Trail**: Complete record of all approvals and executions

---

## Core Application Pages

### 1. Chat Interface (Primary Page)

**Purpose**: Main interaction point with the AI agent

**URL**: `/` (root)

**Required Sections**:

- **Chat Input Area**
  - Large text input field for natural language requests
  - Send button
  - Character count indicator (optional)
  - Clear button to reset conversation

- **Conversation Thread**
  - Scrollable message history
  - User messages (right-aligned, distinct styling)
  - Agent responses (left-aligned, with metadata)
  - Timestamp for each message
  - Status indicators (sending, completed, awaiting approval)

- **Response Metadata Display**
  - Confidence score (when available)
  - Sources cited (knowledge graph references)
  - Action results (tools executed)
  - Error messages (if any)

- **Real-Time Streaming Support**
  - SSE connection status indicator
  - Node progress indicators (planner → approval → executor → responder)
  - Typing indicator during agent processing

**API Integration**:
- `POST /chat` for synchronous requests
- `POST /chat/stream` for streaming responses (recommended for production)

---

### 2. Approval Queue (Modal/Overlay)

**Purpose**: Review and approve/reject proposed actions requiring human intervention

**Trigger**: Automatically appears when agent proposes gated actions (SEND, WRITE, DELETE, PAY)

**Required Sections**:

- **Pending Actions List**
  - Each action card showing:
    - Action ID
    - Tool name (e.g., `send_email`, `slack_post`)
    - Risk tier badge (color-coded: READ=green, SEND=yellow, DELETE=red, PAY=red)
    - Action arguments (formatted, readable)
    - Agent's rationale for the action
  - Expandable details for complex arguments

- **Approval Controls**
  - "Approve All" button (bulk approval)
  - "Reject All" button (bulk rejection)
  - Individual action checkboxes for granular control
  - Per-action approve/reject buttons

- **Context Information**
  - Thread ID
  - User who initiated the request
  - Timestamp

**API Integration**:
- `POST /approve` with thread_id and approval decisions

---

### 3. Thread History (Sidebar or Separate Page)

**Purpose**: View and manage past conversation threads

**Required Sections**:

- **Thread List**
  - Thread ID
  - First message preview
  - Status (completed, awaiting_approval, in_progress)
  - Timestamp
  - Action count (number of tools executed)

- **Thread Detail View**
  - Full conversation history
  - All actions taken (with results)
  - Approval decisions made
  - Sources cited

- **Thread Actions**
  - Resume thread (if awaiting approval)
  - Export thread (JSON/Markdown)
  - Delete thread (with confirmation)

**API Integration**:
- `GET /threads/{thread_id}` to fetch thread state

---

### 4. Knowledge Graph Ingestion (Dedicated Page)

**Purpose**: Upload documents to populate the Personal/Organizational Knowledge Graph

**Required Sections**:

- **Document Upload Form**
  - Title input field
  - Large text area for document content
  - Type selector (doc, default)
  - Scope selector (personal/org)
  - Source ID field (optional, for idempotent re-ingest)
  - Org ACL input (for org scope only - comma-separated permissions)

- **Scope Information**
  - Explanation of personal vs org scope
  - ACL requirements for org scope
  - Permission indicators (what user can write)

- **Ingestion Results**
  - Success confirmation
  - Chunk count
  - Entity IDs created
  - Extraction statistics (if LLM extraction enabled)

**API Integration**:
- `POST /kg/ingest` with document data

---

### 5. OAuth Connections (Settings Page)

**Purpose**: Manage third-party integrations (Google, Slack)

**Required Sections**:

- **Connected Providers List**
  - Provider name (Google, Slack)
  - Connection status (connected/disconnected)
  - Connected account email
  - Last connected timestamp

- **Connect New Provider**
  - "Connect Google" button
  - "Connect Slack" button
  - OAuth flow initiation (redirect or popup)

- **Revoke Connection**
  - Disconnect button per provider
  - Confirmation dialog

**API Integration**:
- `GET /oauth/connections` to list connections
- `GET /oauth/{provider}/connect` to initiate OAuth
- `DELETE /oauth/{provider}` to revoke connection

---

### 6. Settings/Configuration (Optional Admin Page)

**Purpose**: User preferences and system configuration (if admin permissions)

**Required Sections**:

- **User Profile**
  - User ID display
  - Organization ID
  - Roles/permissions display

- **API Configuration** (admin only)
  - Model selection
  - Rate limiting settings
  - Feature toggles

**API Integration**:
- Uses same authentication as other endpoints
- May require additional admin-specific endpoints (future milestone)

---

## HTTP API Specification

### Base URL
```
http://localhost:8000 (configurable via ATLAS_API_HOST/PORT)
```

### Authentication

**Production Mode (OIDC)**:
- Header: `Authorization: Bearer <JWT>`
- JWT validated via RS256 with JWKS
- Required claims: `exp`, `iss`, `aud`, `sub` (user_id), `roles`, `org_id`

**Development Mode (Header Shim)**:
- Headers: `X-Atlas-User-Id`, `X-Atlas-Roles`, `X-Atlas-Org`
- ⚠️ **DEV ONLY - Never expose to internet**

### Endpoints

#### 1. Health Check
```
GET /healthz
```
- **Auth**: None (public)
- **Response**: `{"ok": true}`

#### 2. Chat (Synchronous)
```
POST /chat
```
- **Auth**: Required
- **Rate Limited**: Yes (per principal)
- **Request Body**:
```json
{
  "message": "Send an email to john@example.com about the project update"
}
```
- **Response**:
```json
{
  "ok": true,
  "status": "completed" | "awaiting_approval" | "in_progress",
  "thread_id": "thr_abc123...",
  "response": "I've drafted the email...",
  "pending_actions": [...],
  "sources": [...],
  "confidence": 0.95,
  "action_results": [...]
}
```

#### 3. Chat (Streaming - Recommended)
```
POST /chat/stream
```
- **Auth**: Required
- **Rate Limited**: Yes (per principal)
- **Content-Type**: `text/event-stream`
- **Request Body**: Same as `/chat`
- **Response**: SSE events
  - `open`: `{"thread_id": "..."}`
  - `node`: `{"node": "planner"}` (progress indicator)
  - `awaiting_approval`: `{"status": "awaiting_approval", "pending_actions": [...]}`
  - `completed`: `{"status": "completed", "response": "...", ...}`
  - `error`: `{"code": "internal_error", "message": "..."}`
  - `done`: `{}`

#### 4. Approve Actions
```
POST /approve
```
- **Auth**: Required (must be thread owner)
- **Rate Limited**: Yes (per principal)
- **Request Body**:
```json
{
  "thread_id": "thr_abc123...",
  "approve": true,
  "approved_ids": ["act_xyz..."],
  "rejected_ids": ["act_abc..."]
}
```
- **Response**: Same format as `/chat`

#### 5. Get Thread State
```
GET /threads/{thread_id}
```
- **Auth**: Required (must be thread owner)
- **Rate Limited**: No
- **Response**: Same format as `/chat`

#### 6. Ingest Document
```
POST /kg/ingest
```
- **Auth**: Required
- **Rate Limited**: Yes (per principal)
- **Request Body**:
```json
{
  "text": "Document content here...",
  "title": "Project Documentation",
  "type": "doc",
  "scope": "personal" | "org",
  "source_id": "optional-stable-id",
  "org_acl": ["kg:read:org"]
}
```
- **Response**:
```json
{
  "ok": true,
  "scope": "personal",
  "source_id": "abc123...",
  "chunk_count": 5,
  "entity_ids": ["entity_1", "entity_2", ...]
}
```

#### 7. List OAuth Connections
```
GET /oauth/connections
```
- **Auth**: Required
- **Rate Limited**: No
- **Response**:
```json
{
  "providers": ["google", "slack"]
}
```

#### 8. Initiate OAuth
```
GET /oauth/{provider}/connect
```
- **Auth**: Required
- **Rate Limited**: Yes (per principal)
- **Provider**: `google` or `slack`
- **Response**: 
  - If `Accept: application/json`: `{"authorization_url": "..."}`
  - Otherwise: HTTP 302 redirect to OAuth provider

#### 9. OAuth Callback
```
GET /oauth/{provider}/callback?code=...&state=...
POST /oauth/{provider}/callback
```
- **Auth**: Required (or pending cookie)
- **Rate Limited**: Yes (per IP for GET, per principal for POST)
- **Response**: HTTP 302 redirect to success URL

#### 10. Revoke OAuth
```
DELETE /oauth/{provider}
```
- **Auth**: Required
- **Rate Limited**: Yes (per principal)
- **Response**:
```json
{
  "revoked": "google"
}
```

---

## Data Models

### ChatRequest
```typescript
{
  message: string;  // min_length: 1
}
```

### AgentResponse
```typescript
{
  ok: true;
  status: "completed" | "awaiting_approval" | "in_progress";
  thread_id: string;
  response?: string;
  pending_actions: Array<{
    action_id: string;
    tool: string;
    args: Record<string, any>;
    risk_tier: "read" | "write" | "send" | "delete" | "pay";
    rationale: string;
  }>;
  sources: Array<{
    type: string;
    id: string;
  }>;
  confidence?: number;  // 0.0 to 1.0
  action_results: Array<{
    action_id: string;
    tool: string;
    ok: boolean;
    output?: any;
    error?: string;
  }>;
}
```

### ApproveRequest
```typescript
{
  thread_id: string;
  approve?: boolean;  // Approve/reject ALL
  approved_ids?: string[];  // Granular approval
  rejected_ids?: string[];  // Granular rejection
}
// Validation: Either 'approve' OR approved_ids/rejected_ids, not both
```

### IngestRequest
```typescript
{
  text: string;  // NonEmptyText
  title: string;  // min_length: 1
  type?: string;  // default: "doc"
  scope?: "personal" | "org";  // default: "personal"
  source_id?: string;  // Optional stable id
  org_acl?: string[];  // For org scope only
}
```

### ErrorResponse (All Errors)
```typescript
{
  ok: false;
  error: {
    code: string;  // e.g., "unauthorized", "too_many_requests"
    message: string;
  };
}
```

---

## Risk Tier UI Guidelines

| Risk Tier | Color | Icon | Auto-Run? |
|-----------|-------|------|-----------|
| READ | Green | 👁️ | Yes |
| WRITE | Yellow | ✏️ | No |
| SEND | Orange | 📤 | No |
| DELETE | Red | 🗑️ | No |
| PAY | Red | 💳 | No |

---

## State Management Requirements

### Client-Side State
- **Current thread ID**: Track active conversation
- **Message history**: Maintain conversation context
- **Pending approvals**: Queue of actions awaiting user decision
- **Connection status**: SSE connection health
- **OAuth state**: Track in-progress OAuth flows

### Server-Side State (Threaded)
- Thread state is checkpointed server-side
- Thread ID is returned in first response
- Use thread ID for approval and thread retrieval
- Threads are owner-scoped (RBAC enforced)

---

## Error Handling

### Common Error Codes
- `unauthorized` (401): Missing/invalid token
- `forbidden` (403): Insufficient permissions or not thread owner
- `not_found` (404): Thread not found
- `conflict` (409): Thread not awaiting approval
- `validation_error` (422): Invalid request body
- `too_many_requests` (429): Rate limit exceeded
- `internal_error` (500): Server error

### Error Display
- Show user-friendly message from `error.message`
- Log error code for debugging
- Retry logic for 429 (respect `Retry-After` header)
- No retry for 4xx errors (except 429)

---

## Security Considerations for Front-End

1. **Token Storage**: Store JWT in httpOnly cookies or secure memory (never localStorage)
2. **CSRF Protection**: Include anti-CSRF tokens if using cookie auth
3. **Content Security Policy**: Restrict script sources
4. **XSS Prevention**: Sanitize all user-generated content
5. **OAuth Security**: Use PKCE for OAuth flows (handled by backend)
6. **Rate Limiting**: Respect 429 responses and implement backoff

---

## Responsive Design Requirements

- **Mobile**: Chat interface should be primary focus
- **Tablet**: Split view (chat + thread history)
- **Desktop**: Full dashboard with all sections visible
- **Touch**: Large tap targets for approval actions
- **Keyboard**: Full keyboard navigation support

---

## Accessibility Requirements

- **Screen Reader**: Proper ARIA labels on all interactive elements
- **Keyboard**: Full keyboard navigation (Tab, Enter, Escape)
- **Color Contrast**: WCAG AA compliant (4.5:1 for text)
- **Focus Indicators**: Visible focus states on all interactive elements
- **Error Announcements**: Screen reader announcements for errors

---

## Performance Requirements

- **Initial Load**: < 2 seconds
- **Chat Response**: < 500ms for first streaming event
- **Approval UI**: < 100ms to render approval modal
- **Thread Load**: < 1 second for thread history
- **SSE Reconnection**: Automatic reconnection with exponential backoff

---

## Browser Support

- **Chrome/Edge**: Latest 2 versions
- **Firefox**: Latest 2 versions
- **Safari**: Latest 2 versions
- **Mobile Safari**: iOS 14+
- **Chrome Mobile**: Android 10+

---

## Development Notes

- **API Base URL**: Configurable via environment variables
- **Mock Mode**: Backend supports offline/demo mode with fake tools
- **Streaming**: SSE is recommended for production chat
- **Thread Ownership**: Only thread creator can approve/access threads
- **Idempotency**: Re-ingesting same document with same source_id is idempotent

---

## Future Enhancements (Not in Current Scope)

- Admin UI for policy management
- Per-tool permission configuration
- Thread sharing/delegation
- Advanced search across threads
- Knowledge graph visualization
- Audit log viewer
- Real-time collaboration on threads

---

## Appendix: Converting to PDF

To convert this Markdown document to PDF, use one of the following methods:

### Using Pandoc (Recommended)
```bash
# Install pandoc
brew install pandoc  # macOS
# or
sudo apt-get install pandoc  # Linux

# Convert to PDF
pandoc FRONTEND_DESIGN_SPECIFICATION.md -o FRONTEND_DESIGN_SPECIFICATION.pdf
```

### Using VS Code
1. Install the "Markdown PDF" extension
2. Open the Markdown file
3. Right-click → "Markdown PDF: Export (pdf)"

### Using Online Tools
- https://www.markdowntopdf.com/
- https://dillinger.io/ (export to PDF)

---

*Document Version: 1.0*  
*Generated: July 2026*  
*Based on Atlas Backend: v0.3.3*
