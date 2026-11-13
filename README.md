# ⚽ Dream Stand — Synchronized Football Watch Parties

> **Watch together, wherever you are.** Live and classic football with friends, perfectly synchronized video playback, peer-to-peer video calls, interactive prediction polls, and **@Coach** — an AI match expert grounded in real-time match events.

![Dream Stand](https://img.shields.io/badge/Dream%20Stand-v0.1.0-e50914?style=for-the-badge)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=for-the-badge&logo=vite&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-Database%20%7C%20Auth%20%7C%20Realtime-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![Vercel](https://img.shields.io/badge/Deploy-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)

---

## ⚡ Highlights & Features

- ⏱ **Zero-Spoiler Synchronized Playback**: One party, one moment. All viewers are synchronized within 1.5 seconds via server-anchored playback calculations. When anyone pauses, rewinds, or skips, everyone moves together.
- 📹 **Peer-to-Peer Video & Audio Calls**: Built-in WebRTC video chat with speaking indicators, camera toggles, and host controls without sending audio/video through media servers.
- 🤖 **AI Match Expert (@Coach)**: Ask `@Coach` anything in chat or click *Ask Coach* on any timeline event. Explains offsides, VAR decisions, tactics, and IFAB rules using actual match event data—with automatic anti-spoiler guards preventing answers about future events.
- 📊 **Real-time Prediction Polls**: AI-generated and match-driven prediction polls. Postgres settles results automatically from match event data with a real-time party leaderboard.
- 🛡️ **AI Chat Moderation**: Real-time content screening for abuse, hate speech, and spam while preserving natural football banter.
- 🎨 **Broadcast Stadium Dark UI**: Glassmorphic dark aesthetic, illuminated scoreboards, realistic team crests, and responsive layout built for immersive match viewing.

---

## 🏗️ Architecture

```text
┌────────────────────────────────────────────────────────┐
│               Frontend (Vercel)                        │
│   React 18 + Vite + React Router + Lucide Icons       │
│   - Scorebug & Synchronized YouTube Player             │
│   - Peer-to-Peer WebRTC Video Call Room                │
│   - Live Chat, Timeline, People & Polls Tabs           │
└──────────────────────────┬─────────────────────────────┘
                           │
       WebSocket (Realtime)│ HTTPS REST
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Supabase Backend                     │
│   - Postgres Database (Parties, Members, Messages, etc)│
│   - Row Level Security (RLS) & Stored Procedures (RPC) │
│   - Supabase Realtime Channels (Playback, Chat, Calls) │
│   - Supabase Auth (Email & Password)                   │
│   - Edge Functions (AI Coach, Polls, Moderation)       │
│     * Gemini 3.5 Flash / Claude 3.5 Haiku              │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Node.js (v18+)
- npm / pnpm / yarn
- A [Supabase](https://supabase.com) project (or existing credentials)

### 1. Clone the repository
```bash
git clone https://github.com/<YOUR-USERNAME>/dream-stand.git
cd dream-stand
```

### 2. Install dependencies
```bash
npm install
```

### 3. Configure environment variables
Create a `.env` file in the project root:
```bash
cp .env.example .env
```

Fill in your Supabase project details:
```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-supabase-publishable-key
VITE_LIVE_EPOCH=1793491200
VITE_ICE_SERVERS=
```

### 4. Start the dev server
```bash
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🌐 Deploying to Vercel

Since Dream Stand is a client-side React SPA powered by Supabase Backend-as-a-Service, **you can deploy the entire frontend directly to Vercel without a custom Node.js server!**

### Step-by-Step Vercel Deployment:

1. Push your repository to **GitHub**.
2. Go to your [Vercel Dashboard](https://vercel.com/dashboard) and click **"Add New Project"** → **Import**.
3. Select your `dream-stand` repository.
4. Framework Preset will auto-detect **Vite**.
5. Under **Environment Variables**, add:
   - `VITE_SUPABASE_URL` = *(Your Supabase URL)*
   - `VITE_SUPABASE_PUBLISHABLE_KEY` = *(Your Supabase Anon/Publishable Key)*
   - `VITE_LIVE_EPOCH` = `1793491200` *(Optional)*
6. Click **Deploy**.

> **Note on Client-side Routing**: [`vercel.json`](./vercel.json) is already included with `{ "rewrites": [{ "source": "/(.*)", "destination": "/" }] }` to ensure deep links (like `/party/:id` or `/login`) work smoothly upon browser refresh.

---

## 🧪 How to Test in 3 Minutes

1. **Sign up**: Create an account with any email on the login page and click **Subscribe** → **Yes, subscribe** (mock subscription).
2. **Start a Party**: On the live match (*Barcelona vs Atlético de Madrid*), click **Start Watch Party** → **Create party**.
3. **Invite a Friend**: In the lobby, copy the invite link and paste it into an **Incognito Window**. Create a second account, subscribe, and join the lobby.
4. **Start the Match**: In the host window, click **Start party**. Both windows will enter the room in exact sync. Try pausing, rewinding, or clicking *Go Live*.
5. **Ask Coach**: In chat, type `@Coach why was that a card?` or click **Ask Coach** on any timeline event.
6. **Live Polls**: Check the **Polls** tab to vote on AI-settled prediction questions and watch the party leaderboard update in real-time.

---

## 📁 Project Structure

```text
├── data/                  # Match configs, events & StatsBomb data
├── public/                # Static assets (favicons, logos)
├── src/
│   ├── components/        # Reusable UI components & modals
│   │   ├── call/          # WebRTC video/audio call UI
│   │   ├── panel/         # Chat, Polls, People & Timeline tabs
│   │   └── player/        # Synchronized VideoPlayer & Scorebug
│   ├── context/           # Auth, Party, Call, Invites & Toast state
│   ├── hooks/             # Custom React hooks (player sync, match time)
│   ├── lib/               # Formatters, playback sync math & Supabase client
│   ├── pages/             # Home, Room, Lobby, Login, Invite, Watch
│   └── styles/            # Stadium Night theme (index.css, pages.css, room.css)
├── supabase/
│   ├── functions/         # Deno Edge Functions (Coach, Polls, Moderation)
│   ├── migrations/        # SQL schema, RLS policies, RPC functions
│   └── seed/              # Match seeding scripts
├── vercel.json            # Vercel SPA rewrites
└── vite.config.js         # Vite configuration
```

---

## 📜 License & Credits

- Match event data for the 2022 World Cup final courtesy of **StatsBomb Open Data** (free for non-commercial use).
- Match replays embedded via official YouTube players.
- Built with React, Supabase, and Lucide Icons.
