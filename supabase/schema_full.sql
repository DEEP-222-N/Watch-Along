-- Dream Watch — schema, RLS, RPCs and realtime (HANDOFF.md §6)
create extension if not exists pgcrypto;

-- =====================================================================
-- Tables
-- =====================================================================

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  display_name text not null,
  avatar_color text not null default '#7CFF6B',
  is_subscribed boolean not null default false,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, display_name, avatar_color, is_subscribed)
  values (
    new.id,
    new.email,
    coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'), ''), split_part(new.email, '@', 1)),
    (array['#7CFF6B','#FFB547','#5AC8FA','#FF6B9D','#B18CFF','#FF8A5B','#4FD1C5','#F6E05E'])[1 + (hashtext(new.id::text) & 7)],
    false
  );
  return new;
end $$;

create trigger on_auth_user_created
after insert on auth.users for each row execute function public.handle_new_user();

create table public.matches (
  id text primary key,
  mode text not null check (mode in ('live', 'replay')),
  title text not null,
  competition text,
  youtube_id text not null,
  config jsonb not null,
  sort_order int not null default 0
);

create table public.match_events (
  id text primary key,
  match_id text not null references public.matches(id) on delete cascade,
  period int not null,
  elapsed_in_period_s numeric,
  video_time numeric not null,
  clock text,
  type text not null,
  importance text not null check (importance in ('key', 'detail')),
  team text,
  player text,
  description text not null,
  score_after jsonb,
  data jsonb not null default '{}'::jsonb,
  approximate boolean not null default false
);
create index match_events_match_time_idx on public.match_events (match_id, video_time);

create table public.parties (
  id uuid primary key default gen_random_uuid(),
  match_id text not null references public.matches(id),
  host_id uuid not null references public.profiles(id),
  name text not null,
  status text not null default 'lobby' check (status in ('lobby', 'live', 'ended')),
  is_playing boolean not null default true,
  anchor_position numeric,
  anchor_time double precision,
  live_delay_s numeric not null default 0,
  playback_version int not null default 0,
  settings jsonb not null default '{"ai_moderation": true, "guests_can_poll": false, "allow_cameras": true}'::jsonb,
  created_at timestamptz not null default now(),
  ended_at timestamptz
);

create table public.party_members (
  party_id uuid not null references public.parties(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null default 'guest' check (role in ('host', 'guest')),
  status text not null default 'invited' check (status in ('invited', 'joined', 'removed')),
  muted boolean not null default false,
  team_supported text,
  joined_at timestamptz,
  primary key (party_id, user_id)
);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  party_id uuid not null references public.parties(id) on delete cascade,
  user_id uuid references public.profiles(id),
  author_type text not null default 'user' check (author_type in ('user', 'gaffer', 'system')),
  body text not null check (char_length(body) between 1 and 1000),
  reply_to uuid references public.messages(id) on delete set null,
  event_id text references public.match_events(id) on delete set null,
  video_time numeric,
  meta jsonb not null default '{}'::jsonb,
  flagged boolean not null default false,
  flag_reason text,
  created_at timestamptz not null default now()
);
create index messages_party_created_idx on public.messages (party_id, created_at);

create table public.polls (
  id uuid primary key default gen_random_uuid(),
  party_id uuid not null references public.parties(id) on delete cascade,
  created_by text not null default 'gaffer',
  question text not null,
  options jsonb not null,
  resolve_rule jsonb not null,
  opens_at_video_time numeric not null,
  votes_close_at_video_time numeric not null,
  closes_at_video_time numeric not null,
  status text not null default 'open' check (status in ('open', 'resolved', 'void')),
  correct_option_id text,
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index polls_party_idx on public.polls (party_id, created_at);

create table public.poll_votes (
  poll_id uuid not null references public.polls(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  option_id text not null,
  created_at timestamptz not null default now(),
  primary key (poll_id, user_id)
);

create table public.ai_requests (
  id bigserial primary key,
  user_id uuid not null,
  party_id uuid,
  kind text not null,
  created_at timestamptz not null default now()
);
create index ai_requests_user_time_idx on public.ai_requests (user_id, created_at);
create index ai_requests_party_time_idx on public.ai_requests (party_id, kind, created_at);

-- =====================================================================
-- Helper functions
-- =====================================================================

create or replace function public.is_party_member(pid uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from party_members
    where party_id = pid and user_id = auth.uid() and status <> 'removed'
  );
$$;

create or replace function public.is_party_host(pid uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from parties where id = pid and host_id = auth.uid());
$$;

create or replace function public.get_server_time()
returns double precision language sql stable as $$
  select extract(epoch from clock_timestamp())::double precision;
$$;

-- =====================================================================
-- Row Level Security
-- =====================================================================

alter table public.profiles       enable row level security;
alter table public.matches        enable row level security;
alter table public.match_events   enable row level security;
alter table public.parties        enable row level security;
alter table public.party_members  enable row level security;
alter table public.messages       enable row level security;
alter table public.polls          enable row level security;
alter table public.poll_votes     enable row level security;
alter table public.ai_requests    enable row level security;   -- no policies: service role only

-- Profiles: public fields readable; email is not granted to clients.
create policy "profiles readable" on public.profiles for select to authenticated using (true);
create policy "update own profile" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
revoke select, update on public.profiles from authenticated, anon;
grant select (id, display_name, avatar_color, is_subscribed, created_at) on public.profiles to authenticated;
grant update (display_name, avatar_color) on public.profiles to authenticated;

create policy "matches readable" on public.matches for select to authenticated using (true);
create policy "events readable"  on public.match_events for select to authenticated using (true);

create policy "members read party" on public.parties for select to authenticated
  using (host_id = auth.uid() or public.is_party_member(id));
create policy "host updates party" on public.parties for update to authenticated
  using (host_id = auth.uid()) with check (host_id = auth.uid());

create policy "members read members" on public.party_members for select to authenticated
  using (public.is_party_member(party_id) or public.is_party_host(party_id) or user_id = auth.uid());
create policy "host manages members" on public.party_members for update to authenticated
  using (public.is_party_host(party_id));
create policy "member updates own team" on public.party_members for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
revoke update on public.party_members from authenticated;
grant update (team_supported, muted, status) on public.party_members to authenticated;

create policy "members read messages" on public.messages for select to authenticated
  using (public.is_party_member(party_id));
create policy "members send messages" on public.messages for insert to authenticated
  with check (
    author_type = 'user'
    and user_id = auth.uid()
    and flagged = false
    and public.is_party_member(party_id)
    and not exists (
      select 1 from party_members pm
      where pm.party_id = messages.party_id and pm.user_id = auth.uid() and pm.muted
    )
  );

create policy "members read polls" on public.polls for select to authenticated
  using (public.is_party_member(party_id));
create policy "members read votes" on public.poll_votes for select to authenticated
  using (exists (select 1 from polls p where p.id = poll_id and public.is_party_member(p.party_id)));
create policy "members vote once on open polls" on public.poll_votes for insert to authenticated
  with check (
    user_id = auth.uid()
    and exists (select 1 from polls p where p.id = poll_id and p.status = 'open' and public.is_party_member(p.party_id))
  );

-- =====================================================================
-- RPCs
-- =====================================================================

create or replace function public.check_invites(emails text[])
returns table (email text, status text, display_name text)
language sql security definer stable set search_path = public as $$
  select e.email,
         case when p.id is null then 'no_account'
              when p.is_subscribed then 'subscribed'
              else 'not_subscribed' end,
         p.display_name
  from unnest(emails) as e(email)
  left join profiles p on lower(p.email) = lower(trim(e.email));
$$;

-- p_id lets the client know the invite link before the party exists (shown in the
-- Create Party modal for invitees who aren't subscribed yet).
create or replace function public.create_party(
  p_match_id text, p_name text, p_emails text[], p_id uuid default null, p_settings jsonb default null
)
returns uuid language plpgsql security definer set search_path = public as $$
declare pid uuid; me profiles;
begin
  select * into me from profiles where id = auth.uid();
  if me is null then raise exception 'not signed in'; end if;
  if not me.is_subscribed then raise exception 'subscription required'; end if;

  insert into parties (id, match_id, host_id, name, status, settings)
  values (
    coalesce(p_id, gen_random_uuid()), p_match_id, me.id, p_name, 'lobby',
    coalesce(p_settings, '{"ai_moderation": true, "guests_can_poll": false, "allow_cameras": true}'::jsonb)
  ) returning id into pid;

  insert into party_members (party_id, user_id, role, status, joined_at)
  values (pid, me.id, 'host', 'joined', now());

  insert into party_members (party_id, user_id, role, status)
  select pid, p.id, 'guest', 'invited'
  from profiles p
  where lower(p.email) = any (select lower(trim(x)) from unnest(coalesce(p_emails, '{}')) x)
    and p.is_subscribed and p.id <> me.id
  on conflict do nothing;

  insert into messages (party_id, author_type, body)
  values (pid, 'system', me.display_name || ' created the party');
  return pid;
end $$;

create or replace function public.get_invite_preview(p_party uuid)
returns table (party_id uuid, party_name text, host_name text, host_color text, match_id text, match_title text,
               match_mode text, party_status text, joined_count int, viewer_is_subscribed boolean, viewer_member_status text)
language sql security definer stable set search_path = public as $$
  select pa.id, pa.name, h.display_name, h.avatar_color, m.id, m.title, m.mode, pa.status,
         (select count(*)::int from party_members where party_id = pa.id and status = 'joined'),
         (select is_subscribed from profiles where id = auth.uid()),
         (select status from party_members where party_id = pa.id and user_id = auth.uid())
  from parties pa
  join profiles h on h.id = pa.host_id
  join matches m on m.id = pa.match_id
  where pa.id = p_party;
$$;

create or replace function public.join_party(p_party uuid, p_team text default null)
returns text language plpgsql security definer set search_path = public as $$
declare me profiles; existing party_members; pstatus text;
begin
  select * into me from profiles where id = auth.uid();
  if me is null then raise exception 'not signed in'; end if;
  if not me.is_subscribed then raise exception 'subscription required'; end if;
  select status into pstatus from parties where id = p_party;
  if pstatus is null then raise exception 'party not found'; end if;
  if pstatus = 'ended' then raise exception 'party ended'; end if;
  select * into existing from party_members where party_id = p_party and user_id = me.id;
  if existing.status = 'removed' then raise exception 'removed by host'; end if;

  insert into party_members (party_id, user_id, role, status, team_supported, joined_at)
  values (p_party, me.id, 'guest', 'joined', p_team, now())
  on conflict (party_id, user_id) do update
    set status = 'joined', joined_at = coalesce(party_members.joined_at, now()),
        team_supported = coalesce(excluded.team_supported, party_members.team_supported);

  if existing.status is distinct from 'joined' then
    insert into messages (party_id, author_type, body)
    values (p_party, 'system', me.display_name || ' joined the party');
  end if;
  return pstatus;
end $$;

create or replace function public.mock_subscribe()
returns void language sql security definer set search_path = public as $$
  update profiles set is_subscribed = true where id = auth.uid();
$$;

create or replace function public.report_message(p_message uuid)
returns void language plpgsql security definer set search_path = public as $$
declare pid uuid;
begin
  select party_id into pid from messages where id = p_message;
  if pid is null or not public.is_party_member(pid) then raise exception 'not a member'; end if;
  update messages set flagged = true, flag_reason = coalesce(flag_reason, 'Reported by a member')
  where id = p_message and author_type = 'user';
end $$;

create or replace function public.unflag_message(p_message uuid)
returns void language plpgsql security definer set search_path = public as $$
declare pid uuid;
begin
  select party_id into pid from messages where id = p_message;
  if pid is null or not public.is_party_host(pid) then raise exception 'host only'; end if;
  update messages set flagged = false where id = p_message;
end $$;

-- Deterministic: the answer comes from match_events, never from the caller.
create or replace function public.resolve_poll(p_poll uuid)
returns text language plpgsql security definer set search_path = public as $$
declare p polls; mid text; r jsonb; ans text; t text;
begin
  select * into p from polls where id = p_poll;
  if p is null then raise exception 'poll not found'; end if;
  if p.status <> 'open' then return p.correct_option_id; end if;
  if not public.is_party_member(p.party_id) then raise exception 'not a member'; end if;
  select match_id into mid from parties where id = p.party_id;
  r := p.resolve_rule;

  if r->>'kind' = 'goal_in_window' then
    ans := case when exists (select 1 from match_events where match_id = mid and type = 'goal'
             and video_time > p.opens_at_video_time and video_time <= p.closes_at_video_time) then 'yes' else 'no' end;
  elsif r->>'kind' = 'card_in_window' then
    ans := case when exists (select 1 from match_events where match_id = mid and type = 'card'
             and video_time > p.opens_at_video_time and video_time <= p.closes_at_video_time) then 'yes' else 'no' end;
  elsif r->>'kind' = 'player_scores_in_window' then
    ans := case when exists (select 1 from match_events where match_id = mid and type = 'goal' and player = r->>'player'
             and video_time > p.opens_at_video_time and video_time <= p.closes_at_video_time) then 'yes' else 'no' end;
  elsif r->>'kind' in ('next_goal_team', 'next_card_team') then
    select team into t from match_events
      where match_id = mid and type = case when r->>'kind' = 'next_goal_team' then 'goal' else 'card' end
        and video_time > p.opens_at_video_time and video_time <= p.closes_at_video_time
      order by video_time limit 1;
    ans := coalesce(t, 'none');
  elsif r->>'kind' = 'shootout_kick_scored' then
    select case when description ilike '%SCORES%' then 'yes' else 'no' end into ans from match_events
      where match_id = mid and type = 'shootout_kick'
        and video_time > p.opens_at_video_time and video_time <= p.closes_at_video_time
      order by video_time limit 1;
    if ans is null then
      update polls set status = 'void', resolved_at = now() where id = p_poll;
      return null;
    end if;
  else
    update polls set status = 'void', resolved_at = now() where id = p_poll;
    return null;
  end if;

  update polls set status = 'resolved', correct_option_id = ans, resolved_at = now() where id = p_poll;
  insert into messages (party_id, author_type, body, meta)
  values (p.party_id, 'system', 'Poll result: ' || p.question || ' → ' ||
          coalesce((select o->>'label' from jsonb_array_elements(p.options) o where o->>'id' = ans), ans),
          jsonb_build_object('poll_id', p.id));
  return ans;
end $$;

create or replace function public.void_poll(p_poll uuid)
returns void language plpgsql security definer set search_path = public as $$
declare pid uuid;
begin
  select party_id into pid from polls where id = p_poll;
  if pid is null or not public.is_party_host(pid) then raise exception 'host only'; end if;
  update polls set status = 'void', resolved_at = now() where id = p_poll and status = 'open';
end $$;

-- Host-only system message (full time, etc.). Clients cannot insert system rows directly.
create or replace function public.post_system_message(p_party uuid, p_body text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_party_host(p_party) then raise exception 'host only'; end if;
  insert into messages (party_id, author_type, body) values (p_party, 'system', left(p_body, 1000));
end $$;

revoke execute on function public.check_invites(text[]), public.create_party(text, text, text[], uuid, jsonb),
  public.get_invite_preview(uuid), public.join_party(uuid, text), public.mock_subscribe(),
  public.report_message(uuid), public.unflag_message(uuid), public.resolve_poll(uuid), public.void_poll(uuid),
  public.post_system_message(uuid, text) from public, anon;
grant execute on function public.check_invites(text[]), public.create_party(text, text, text[], uuid, jsonb),
  public.get_invite_preview(uuid), public.join_party(uuid, text), public.mock_subscribe(),
  public.report_message(uuid), public.unflag_message(uuid), public.resolve_poll(uuid), public.void_poll(uuid),
  public.post_system_message(uuid, text), public.get_server_time() to authenticated;
grant execute on function public.get_server_time() to anon;

-- =====================================================================
-- Guard trigger on party_members (§6.5)
-- =====================================================================

create or replace function public.guard_member_update()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;   -- service role
  if public.is_party_host(new.party_id) then
    if old.user_id = auth.uid() and (new.status <> old.status or new.muted <> old.muted) then
      raise exception 'host cannot mute or remove themselves';
    end if;
    return new;
  end if;
  if old.user_id <> auth.uid() then raise exception 'not allowed'; end if;
  if new.status <> old.status or new.muted <> old.muted or new.role <> old.role then
    raise exception 'only the host can change status or mute';
  end if;
  return new;
end $$;

create trigger party_members_guard before update on public.party_members
for each row execute function public.guard_member_update();

-- =====================================================================
-- Realtime
-- =====================================================================

alter publication supabase_realtime add table
  public.parties, public.party_members, public.messages, public.polls, public.poll_votes;
-- Dream Watch — shared playback controls, playback chat logs, and the invite-join fix.

-- ---------------------------------------------------------------------
-- 1. Member guard: only police direct client updates.
--    The old trigger was SECURITY DEFINER and keyed off auth.uid(), so it also
--    blocked join_party() (a definer RPC run *for* the user) from turning an
--    'invited' row into 'joined'. As SECURITY INVOKER, current_user is
--    'authenticated' only for direct client writes; RPCs run as their owner.
-- ---------------------------------------------------------------------
create or replace function public.guard_member_update()
returns trigger language plpgsql security invoker set search_path = public as $$
begin
  if current_user not in ('authenticated', 'anon') then return new; end if;  -- RPCs and service role
  if public.is_party_host(new.party_id) then
    if old.user_id = auth.uid() and (new.status <> old.status or new.muted <> old.muted) then
      raise exception 'host cannot mute or remove themselves';
    end if;
    return new;
  end if;
  if old.user_id <> auth.uid() then raise exception 'not allowed'; end if;
  if new.status <> old.status or new.muted <> old.muted or new.role <> old.role then
    raise exception 'only the host can change status or mute';
  end if;
  return new;
end $$;

-- ---------------------------------------------------------------------
-- 2. Who last changed playback ("Paused by Riya").
-- ---------------------------------------------------------------------
alter table public.parties add column if not exists playback_by uuid references public.profiles(id);

alter table public.parties alter column settings
  set default '{"ai_moderation": true, "guests_can_poll": false, "allow_cameras": true, "shared_controls": true}'::jsonb;

-- ---------------------------------------------------------------------
-- 3. Shared playback control.
--    Any joined member may change playback (unless the host turned
--    settings.shared_controls off). Only the playback columns can change, the
--    version is bumped server-side, and a chat log line is written from a fixed
--    vocabulary, so members can't post arbitrary system messages.
--    Rapid repeats by the same person (e.g. three "10 s back" taps) update one
--    log line instead of flooding the chat.
-- ---------------------------------------------------------------------
create or replace function public.playback_action(
  p_party uuid, p_action text, p_patch jsonb, p_label text default null
)
returns int language plpgsql security definer set search_path = public as $$
declare pa parties; me profiles; v int; log_line text; recent uuid;
begin
  select * into pa from parties where id = p_party;
  if pa is null then raise exception 'party not found'; end if;
  if pa.status <> 'live' then raise exception 'party not live'; end if;
  if not exists (select 1 from party_members where party_id = p_party and user_id = auth.uid() and status = 'joined') then
    raise exception 'not a member';
  end if;
  if pa.host_id <> auth.uid() and coalesce(pa.settings->>'shared_controls', 'true') = 'false' then
    raise exception 'host controls playback';
  end if;
  select * into me from profiles where id = auth.uid();

  update parties set
    is_playing      = case when p_patch ? 'is_playing'      then (p_patch->>'is_playing')::boolean else is_playing end,
    anchor_position = case when p_patch ? 'anchor_position' then (p_patch->>'anchor_position')::numeric else anchor_position end,
    anchor_time     = case when p_patch ? 'anchor_time'     then (p_patch->>'anchor_time')::double precision else anchor_time end,
    live_delay_s    = case when p_patch ? 'live_delay_s'    then greatest(0, (p_patch->>'live_delay_s')::numeric) else live_delay_s end,
    playback_version = playback_version + 1,
    playback_by     = auth.uid()
  where id = p_party
  returning playback_version into v;

  if p_label is not null and p_label !~ '^[0-9]{1,3}:[0-9]{2}$' then p_label := null; end if;
  log_line := me.display_name || ' ' || case p_action
    when 'pause'        then 'paused the video'
    when 'play'         then 'resumed the video'
    when 'go_live'      then 'went back to live'
    when 'skip_back'    then 'went back to ' || coalesce(p_label, 'an earlier moment')
    when 'skip_forward' then 'skipped ahead to ' || coalesce(p_label, 'a later moment')
    when 'seek'         then 'jumped to ' || coalesce(p_label, 'a new moment')
    else 'changed playback'
  end;

  select id into recent from messages
   where party_id = p_party and author_type = 'system'
     and meta->>'kind' = 'playback' and meta->>'actor' = auth.uid()::text
     and meta->>'action' = p_action
     and created_at > now() - interval '5 seconds'
   order by created_at desc limit 1;

  if recent is not null then
    update messages set body = log_line where id = recent;
  else
    insert into messages (party_id, author_type, body, meta)
    values (p_party, 'system', log_line, jsonb_build_object('kind', 'playback', 'actor', auth.uid(), 'action', p_action));
  end if;
  return v;
end $$;

revoke execute on function public.playback_action(uuid, text, jsonb, text) from public, anon;
grant execute on function public.playback_action(uuid, text, jsonb, text) to authenticated;
-- Dream Watch — hosts can delete a party; guests can leave one (or decline an invite).

alter table public.parties add column if not exists deleted_at timestamptz;

-- 'left' = the member chose to leave. Unlike 'removed', they can rejoin via the invite link.
alter table public.party_members drop constraint if exists party_members_status_check;
alter table public.party_members add constraint party_members_status_check
  check (status in ('invited', 'joined', 'removed', 'left'));

-- Only invited and joined members count as members (RLS, chat, polls, Edge Functions).
create or replace function public.is_party_member(pid uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from party_members
    where party_id = pid and user_id = auth.uid() and status in ('invited', 'joined')
  );
$$;

-- Host-only. Soft delete: the party ends for anyone still in the room (they get the
-- realtime UPDATE and see the recap), and it disappears from every list and invite link.
create or replace function public.delete_party(p_party uuid)
returns void language plpgsql security definer set search_path = public as $$
declare me profiles;
begin
  if not public.is_party_host(p_party) then raise exception 'host only'; end if;
  select * into me from profiles where id = auth.uid();
  insert into messages (party_id, author_type, body)
  values (p_party, 'system', me.display_name || ' deleted the party');
  update parties
     set status = 'ended', ended_at = coalesce(ended_at, now()), is_playing = false, deleted_at = now()
   where id = p_party;
end $$;

-- A guest leaves a party (or declines an invite). The host deletes instead.
create or replace function public.leave_party(p_party uuid)
returns void language plpgsql security definer set search_path = public as $$
declare me profiles; mine party_members;
begin
  select * into me from profiles where id = auth.uid();
  select * into mine from party_members where party_id = p_party and user_id = auth.uid();
  if mine is null or mine.status not in ('invited', 'joined') then raise exception 'not a member'; end if;
  if mine.role = 'host' then raise exception 'host must delete the party instead'; end if;
  update party_members set status = 'left' where party_id = p_party and user_id = auth.uid();
  if mine.status = 'joined' then
    insert into messages (party_id, author_type, body)
    values (p_party, 'system', me.display_name || ' left the party');
  end if;
end $$;

-- Deleted parties behave as "not found" for invite links and joining.
create or replace function public.get_invite_preview(p_party uuid)
returns table (party_id uuid, party_name text, host_name text, host_color text, match_id text, match_title text,
               match_mode text, party_status text, joined_count int, viewer_is_subscribed boolean, viewer_member_status text)
language sql security definer stable set search_path = public as $$
  select pa.id, pa.name, h.display_name, h.avatar_color, m.id, m.title, m.mode, pa.status,
         (select count(*)::int from party_members where party_id = pa.id and status = 'joined'),
         (select is_subscribed from profiles where id = auth.uid()),
         (select status from party_members where party_id = pa.id and user_id = auth.uid())
  from parties pa
  join profiles h on h.id = pa.host_id
  join matches m on m.id = pa.match_id
  where pa.id = p_party and pa.deleted_at is null;
$$;

create or replace function public.join_party(p_party uuid, p_team text default null)
returns text language plpgsql security definer set search_path = public as $$
declare me profiles; existing party_members; pstatus text;
begin
  select * into me from profiles where id = auth.uid();
  if me is null then raise exception 'not signed in'; end if;
  if not me.is_subscribed then raise exception 'subscription required'; end if;
  select status into pstatus from parties where id = p_party and deleted_at is null;
  if pstatus is null then raise exception 'party not found'; end if;
  if pstatus = 'ended' then raise exception 'party ended'; end if;
  select * into existing from party_members where party_id = p_party and user_id = me.id;
  if existing.status = 'removed' then raise exception 'removed by host'; end if;

  insert into party_members (party_id, user_id, role, status, team_supported, joined_at)
  values (p_party, me.id, 'guest', 'joined', p_team, now())
  on conflict (party_id, user_id) do update
    set status = 'joined', joined_at = coalesce(party_members.joined_at, now()),
        team_supported = coalesce(excluded.team_supported, party_members.team_supported);

  if existing.status is distinct from 'joined' then
    insert into messages (party_id, author_type, body)
    values (p_party, 'system', me.display_name || case when existing.status = 'left' then ' rejoined the party' else ' joined the party' end);
  end if;
  return pstatus;
end $$;

revoke execute on function public.delete_party(uuid), public.leave_party(uuid) from public, anon;
grant execute on function public.delete_party(uuid), public.leave_party(uuid) to authenticated;
-- Dream Watch — keep the source order of events that share a video timestamp
-- (e.g. a foul, the card for it and the penalty goal all at the same second).
alter table public.match_events add column if not exists seq int;
create index if not exists match_events_match_time_seq_idx on public.match_events (match_id, video_time, seq);


-- =====================================================================
-- Seed Matches & Events Data
-- =====================================================================
INSERT INTO public.matches (id, mode, title, competition, youtube_id, config, sort_order)
VALUES ('barca-atleti-2025-md19', 'live', 'Barcelona vs Atlético de Madrid', 'LaLiga 2025/26 — Matchday 19', 'oW8psSa2hf4', '{"id":"barca-atleti-2025-md19","mode":"live","title":"Barcelona vs Atlético de Madrid","competition":"LaLiga 2025/26 — Matchday 19","venue":"Spotify Camp Nou, Barcelona","date":"2025-12-02","home":"Barcelona","away":"Atlético de Madrid","youtube_id":"oW8psSa2hf4","period_starts":{"1":186,"2":3333},"period_ends":{"1":3156,"2":6491},"period_base_minute":{"1":0,"2":45},"period_length_min":{"1":45,"2":45},"loop":{"start":186,"end":6491},"teams":{"Barcelona":{"short":"BAR","color":"#4C8DF6","text":"#8DB6FF"},"Atlético de Madrid":{"short":"ATM","color":"#E5484D","text":"#FF8B8F"}},"lineups":{"Barcelona":{"formation":"4-2-3-1","manager":"Hansi Flick","starting_xi":["Joan García","Jules Koundé","Pau Cubarsí","Gerard Martín","Alejandro Balde","Eric García","Pedri","Lamine Yamal","Dani Olmo","Raphinha","Robert Lewandowski"]},"Atlético de Madrid":{"formation":"4-2-3-1","manager":"Diego Simeone","starting_xi":["Jan Oblak","Nahuel Molina","José María Giménez","Clément Lenglet","Dávid Hancko","Johnny Cardoso","Pablo Barrios","Giuliano Simeone","Álex Baena","Nico González","Julián Alvarez"]}},"referee":"Ricardo de Burgos Bengoetxea (VAR: Pablo González Fuertes)","full_time_stats":{"possession":"58.2% – 41.8%","shots":"19 – 7","shots_on_target":"6 – 2","expected_goals":"3.88 – 0.97","corners":"5 – 4","fouls":"12 – 9","offsides":"1 – 4","yellow_cards":"1 – 1","penalties":"1 (0 scored) – 0"},"events_file":"barca_atleti_events.json","data_credit":"Event data compiled from LaLiga''s official minute-by-minute match record and published match reports; times accurate to the minute"}'::jsonb, 0)
ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, sort_order = EXCLUDED.sort_order;
DELETE FROM public.match_events WHERE match_id = 'barca-atleti-2025-md19';
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-001', 'barca-atleti-2025-md19', 1, NULL, 186, '1''', 'period_start', 'key', NULL, NULL, 'Kick-off: 1st half begins', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"stats_after":{"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 1);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-002', 'barca-atleti-2025-md19', 1, NULL, 546, '6''', 'foul', 'detail', 'Atlético de Madrid', 'Álex Baena', 'Foul by Álex Baena (Atlético de Madrid) on Jules Koundé; Barcelona get a free kick on the right wing', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"victim":"Jules Koundé","free_kick_for":"Barcelona","free_kick_zone":"on the right wing","stats_after":{"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 2);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-003', 'barca-atleti-2025-md19', 1, NULL, 606, '7''', 'injury', 'detail', 'Atlético de Madrid', 'Johnny Cardoso', 'Play stopped for treatment to Johnny Cardoso (Atlético de Madrid)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"stats_after":{"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 3);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-004', 'barca-atleti-2025-md19', 1, NULL, 726, '9''', 'shot', 'detail', 'Barcelona', 'Robert Lewandowski', 'Chance for Barcelona: Robert Lewandowski''s right-footed shot from outside the box is blocked by a defender (set up by Dani Olmo)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":"Dani Olmo","assist_type":null,"stats_after":{"Barcelona":{"shots":1,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 4);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-005', 'barca-atleti-2025-md19', 1, NULL, 726, '9''', 'shot', 'detail', 'Barcelona', 'Raphinha', 'Chance for Barcelona: Raphinha''s left-footed shot from outside the box goes off target — just over the bar (set up by Robert Lewandowski)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"outside the box","assist":"Robert Lewandowski","assist_type":null,"stats_after":{"Barcelona":{"shots":2,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 5);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-006', 'barca-atleti-2025-md19', 1, NULL, 906, '12''', 'shot', 'detail', 'Barcelona', 'Raphinha', 'Chance for Barcelona: Raphinha''s right-footed shot from the centre of the box is blocked by a defender (set up by Dani Olmo)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"the centre of the box","assist":"Dani Olmo","assist_type":null,"stats_after":{"Barcelona":{"shots":3,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 6);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-007', 'barca-atleti-2025-md19', 1, NULL, 966, '13''', 'corner', 'detail', 'Atlético de Madrid', NULL, 'Corner to Atlético de Madrid (conceded by Gerard Martín)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"conceded_by":"Gerard Martín","stats_after":{"Barcelona":{"shots":3,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 7);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-008', 'barca-atleti-2025-md19', 1, NULL, 966, '13''', 'injury', 'detail', 'Atlético de Madrid', 'Johnny Cardoso', 'Play stopped for treatment to Johnny Cardoso (Atlético de Madrid). He goes down again and can''t continue', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"stats_after":{"Barcelona":{"shots":3,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 8);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-009', 'barca-atleti-2025-md19', 1, NULL, 1026, '14''', 'substitution', 'key', 'Atlético de Madrid', 'Koke', 'Substitution, Atlético de Madrid: Koke comes on for Johnny Cardoso (injury). An early, forced change for Simeone', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"player_on":"Koke","player_off":"Johnny Cardoso","reason":"Injury","stats_after":{"Barcelona":{"shots":3,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 9);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-010', 'barca-atleti-2025-md19', 1, NULL, 1086, '15''', 'shot', 'detail', 'Barcelona', 'Lamine Yamal', 'Chance for Barcelona: Lamine Yamal''s left-footed shot from outside the box goes off target — high and wide (set up by Pedri)', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"outside the box","assist":"Pedri","assist_type":null,"stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 10);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-011', 'barca-atleti-2025-md19', 1, NULL, 1146, '16''', 'foul', 'detail', 'Barcelona', 'Dani Olmo', 'Foul by Dani Olmo (Barcelona) on Pablo Barrios; Atlético de Madrid get a free kick in their own half', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"victim":"Pablo Barrios","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 11);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-012', 'barca-atleti-2025-md19', 1, NULL, 1206, '17''', 'foul', 'detail', 'Barcelona', 'Jules Koundé', 'Foul by Jules Koundé (Barcelona) on Dávid Hancko; Atlético de Madrid get a free kick on the left wing', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"victim":"Dávid Hancko","free_kick_for":"Atlético de Madrid","free_kick_zone":"on the left wing","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 12);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-013', 'barca-atleti-2025-md19', 1, NULL, 1206, '17''', 'foul', 'detail', 'Atlético de Madrid', 'José María Giménez', 'Foul by José María Giménez (Atlético de Madrid) on Pedri; Barcelona get a free kick in their own half', '{"Barcelona":0,"Atlético de Madrid":0}'::jsonb, '{"victim":"Pedri","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":0,"shots_on_target":0,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 13);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-014', 'barca-atleti-2025-md19', 1, NULL, 1326, '19''', 'goal', 'key', 'Atlético de Madrid', 'Álex Baena', 'GOAL! Álex Baena scores for Atlético de Madrid — right foot from the centre of the box, into the centre of the goal (assist: Nahuel Molina, on a fast break). Molina''s lofted ball over the top caught Barcelona''s high defensive line. The goal was checked by VAR before being confirmed. Score: Barcelona 0–1 Atlético de Madrid', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"body_part":"right foot","location":"the centre of the box","placement":"centre of the goal","assist":"Nahuel Molina","assist_type":"on a fast break","penalty":false,"stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 14);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-015', 'barca-atleti-2025-md19', 1, NULL, 1386, '20''', 'var_decision', 'key', 'Atlético de Madrid', NULL, 'VAR decision: Goal confirmed — Álex Baena''s goal stands. The data does not record what was checked; a possible offside in the build-up is the usual reason for this kind of review', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"decision":"Goal confirmed — Álex Baena''s goal stands","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 15);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-016', 'barca-atleti-2025-md19', 1, NULL, 1446, '21''', 'foul', 'detail', 'Atlético de Madrid', 'Julián Alvarez', 'Foul by Julián Alvarez (Atlético de Madrid) on Dani Olmo; Barcelona get a free kick in their own half', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"victim":"Dani Olmo","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":3,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 16);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-017', 'barca-atleti-2025-md19', 1, NULL, 1506, '22''', 'foul', 'detail', 'Atlético de Madrid', 'Nahuel Molina', 'Foul by Nahuel Molina (Atlético de Madrid) on Raphinha; Barcelona get a free kick on the left wing', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"victim":"Raphinha","free_kick_for":"Barcelona","free_kick_zone":"on the left wing","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":4,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 17);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-018', 'barca-atleti-2025-md19', 1, NULL, 1506, '22''', 'foul', 'detail', 'Atlético de Madrid', 'Pablo Barrios', 'Foul by Pablo Barrios (Atlético de Madrid) on Eric García; Barcelona get a free kick on the right wing', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"victim":"Eric García","free_kick_for":"Barcelona","free_kick_zone":"on the right wing","stats_after":{"Barcelona":{"shots":4,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 18);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-019', 'barca-atleti-2025-md19', 1, NULL, 1566, '23''', 'shot', 'detail', 'Barcelona', 'Alejandro Balde', 'Chance for Barcelona: Alejandro Balde''s left-footed shot from outside the box goes off target (set up by Gerard Martín)', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"outside the box","assist":"Gerard Martín","assist_type":null,"stats_after":{"Barcelona":{"shots":5,"shots_on_target":0,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 19);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-020', 'barca-atleti-2025-md19', 1, NULL, 1626, '24''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by José María Giménez)', '{"Barcelona":0,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"José María Giménez","stats_after":{"Barcelona":{"shots":5,"shots_on_target":0,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 20);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-021', 'barca-atleti-2025-md19', 1, NULL, 1746, '26''', 'goal', 'key', 'Barcelona', 'Raphinha', 'GOAL! Raphinha scores for Barcelona — right foot from the right side of the box, into the bottom right corner (assist: Pedri, with a through ball). Raphinha''s first touch took him around goalkeeper Jan Oblak and he finished into the empty net. Score: Barcelona 1–1 Atlético de Madrid', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"body_part":"right foot","location":"the right side of the box","placement":"bottom right corner","assist":"Pedri","assist_type":"with a through ball","penalty":false,"stats_after":{"Barcelona":{"shots":6,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 21);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-022', 'barca-atleti-2025-md19', 1, NULL, 1806, '27''', 'shot', 'detail', 'Barcelona', 'Alejandro Balde', 'Chance for Barcelona: Alejandro Balde''s left-footed shot from a difficult angle on the left goes off target — high and wide (set up by Raphinha)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"a difficult angle on the left","assist":"Raphinha","assist_type":null,"stats_after":{"Barcelona":{"shots":7,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 22);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-023', 'barca-atleti-2025-md19', 1, NULL, 1866, '28''', 'offside', 'detail', 'Atlético de Madrid', 'Nahuel Molina', 'Offside: Nahuel Molina (Atlético de Madrid) is flagged offside', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":7,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 23);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-024', 'barca-atleti-2025-md19', 1, NULL, 1926, '29''', 'shot', 'detail', 'Barcelona', 'Lamine Yamal', 'Chance for Barcelona: Lamine Yamal''s left-footed shot from the right side of the box is blocked by a defender (set up by Pedri)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"blocked","body_part":"Left foot","location":"the right side of the box","assist":"Pedri","assist_type":null,"stats_after":{"Barcelona":{"shots":8,"shots_on_target":1,"corners":1,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 24);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-025', 'barca-atleti-2025-md19', 1, NULL, 1986, '30''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Pablo Barrios)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Pablo Barrios","stats_after":{"Barcelona":{"shots":8,"shots_on_target":1,"corners":2,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 25);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-026', 'barca-atleti-2025-md19', 1, NULL, 2166, '33''', 'shot', 'detail', 'Barcelona', 'Robert Lewandowski', 'Chance for Barcelona: Robert Lewandowski''s right-footed shot from outside the box is blocked by a defender (set up by Raphinha)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":"Raphinha","assist_type":null,"stats_after":{"Barcelona":{"shots":9,"shots_on_target":1,"corners":2,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":5,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 26);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-027', 'barca-atleti-2025-md19', 1, NULL, 2286, '35''', 'penalty_awarded', 'key', 'Atlético de Madrid', 'Pablo Barrios', 'PENALTY to Barcelona: Pablo Barrios (Atlético de Madrid) fouls Dani Olmo inside the penalty area', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"offence":"Foul","victim":"Dani Olmo","penalty_for":"Barcelona","stats_after":{"Barcelona":{"shots":9,"shots_on_target":1,"corners":2,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":6,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 27);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-028', 'barca-atleti-2025-md19', 1, NULL, 2346, '36''', 'penalty_missed', 'key', 'Barcelona', 'Robert Lewandowski', 'PENALTY MISSED: Robert Lewandowski (Barcelona) — right-footed shot high and wide to the left of Oblak''s goal. A big chance to make it 2–1 goes begging', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","where":"high and wide to the left of Oblak''s goal","stats_after":{"Barcelona":{"shots":10,"shots_on_target":1,"corners":2,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":6,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 28);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-029', 'barca-atleti-2025-md19', 1, NULL, 2466, '38''', 'shot', 'key', 'Barcelona', 'Robert Lewandowski', 'Chance for Barcelona: Robert Lewandowski''s header from the centre of the box is saved — Oblak saves low to his left (set up by Lamine Yamal, with a cross)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"saved","body_part":"Head","location":"the centre of the box","assist":"Lamine Yamal","assist_type":"with a cross","stats_after":{"Barcelona":{"shots":11,"shots_on_target":2,"corners":2,"fouls":2,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":6,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 29);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-030', 'barca-atleti-2025-md19', 1, NULL, 2526, '39''', 'foul', 'detail', 'Barcelona', 'Dani Olmo', 'Foul by Dani Olmo (Barcelona) on Álex Baena; Atlético de Madrid get a free kick on the left wing', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Álex Baena","free_kick_for":"Atlético de Madrid","free_kick_zone":"on the left wing","stats_after":{"Barcelona":{"shots":11,"shots_on_target":2,"corners":2,"fouls":3,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":6,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 30);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-031', 'barca-atleti-2025-md19', 1, NULL, 2646, '41''', 'shot', 'key', 'Barcelona', 'Alejandro Balde', 'Chance for Barcelona: Alejandro Balde''s left-footed shot from the left side of the box is saved — Oblak gets down to it (set up by Raphinha, with a headed pass)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"saved","body_part":"Left foot","location":"the left side of the box","assist":"Raphinha","assist_type":"with a headed pass","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":3,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":6,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 31);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-032', 'barca-atleti-2025-md19', 1, NULL, 2646, '41''', 'foul', 'detail', 'Atlético de Madrid', 'Álex Baena', 'Foul by Álex Baena (Atlético de Madrid) on Pau Cubarsí; Barcelona get a free kick in their own half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Pau Cubarsí","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":3,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 32);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-033', 'barca-atleti-2025-md19', 1, NULL, 2646, '41''', 'card', 'key', 'Atlético de Madrid', 'Álex Baena', 'YELLOW CARD: Álex Baena (Atlético de Madrid) is booked — a bad foul on Pau Cubarsí. Match reports describe him landing on Cubarsí with no real attempt to play the ball', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"card":"Yellow Card","reason":"a bad foul on Pau Cubarsí","is_manager":false,"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":3,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 33);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-034', 'barca-atleti-2025-md19', 1, NULL, 2886, '45''', 'added_time', 'detail', NULL, NULL, 'Fourth official signals 4 minutes of added time', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"minutes":4,"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":3,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 34);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-035', 'barca-atleti-2025-md19', 1, NULL, 3006, '45+2''', 'foul', 'detail', 'Barcelona', 'Gerard Martín', 'Foul by Gerard Martín (Barcelona) on Giuliano Simeone; Atlético de Madrid get a free kick on the right wing', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Giuliano Simeone","free_kick_for":"Atlético de Madrid","free_kick_zone":"on the right wing","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":4,"offsides":0,"yellow_cards":0},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 35);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-036', 'barca-atleti-2025-md19', 1, NULL, 3006, '45+2''', 'card', 'key', 'Barcelona', 'Gerard Martín', 'YELLOW CARD: Gerard Martín (Barcelona) is booked — a bad, clumsy foul on Giuliano Simeone', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"card":"Yellow Card","reason":"a bad, clumsy foul on Giuliano Simeone","is_manager":false,"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":4,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 36);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-037', 'barca-atleti-2025-md19', 1, NULL, 3006, '45+2''', 'injury', 'detail', 'Atlético de Madrid', 'Giuliano Simeone', 'Play stopped for treatment to Giuliano Simeone (Atlético de Madrid)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":4,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 37);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-038', 'barca-atleti-2025-md19', 1, NULL, 3066, '45+3''', 'foul', 'detail', 'Barcelona', 'Alejandro Balde', 'Foul by Alejandro Balde (Barcelona) on Giuliano Simeone; Atlético de Madrid get a free kick in their own half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Giuliano Simeone","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":5,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 38);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-039', 'barca-atleti-2025-md19', 1, NULL, 3126, '45+4''', 'period_end', 'key', NULL, NULL, 'Half-time (4 minutes of added time were played)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"added_minutes":4,"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":5,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 39);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-040', 'barca-atleti-2025-md19', 2, NULL, 3333, '46''', 'substitution', 'key', 'Atlético de Madrid', 'Conor Gallagher', 'Substitution, Atlético de Madrid: Conor Gallagher comes on for Nico González. Half-time change by Simeone', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Conor Gallagher","player_off":"Nico González","reason":"Tactical","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":5,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 40);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-041', 'barca-atleti-2025-md19', 2, NULL, 3333, '46''', 'period_start', 'key', NULL, NULL, '2nd half begins', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":5,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 41);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-042', 'barca-atleti-2025-md19', 2, NULL, 3393, '46''', 'offside', 'detail', 'Atlético de Madrid', 'Álex Baena', 'Offside: Álex Baena (Atlético de Madrid) is flagged offside', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":5,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 42);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-043', 'barca-atleti-2025-md19', 2, NULL, 3513, '48''', 'foul', 'detail', 'Barcelona', 'Pau Cubarsí', 'Foul by Pau Cubarsí (Barcelona) on Álex Baena; Atlético de Madrid get a free kick in their own half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Álex Baena","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":6,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 43);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-044', 'barca-atleti-2025-md19', 2, NULL, 3693, '51''', 'foul', 'detail', 'Barcelona', 'Robert Lewandowski', 'Foul by Robert Lewandowski (Barcelona) on Clément Lenglet; Atlético de Madrid get a free kick in their own half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Clément Lenglet","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":7,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":1,"shots_on_target":1,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 44);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-045', 'barca-atleti-2025-md19', 2, NULL, 3753, '52''', 'shot', 'key', 'Atlético de Madrid', 'Julián Alvarez', 'Chance for Atlético de Madrid: Julián Alvarez''s right-footed shot from the right side of the box is saved — Joan García saves in the centre of the goal (set up by Nahuel Molina)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"saved","body_part":"Right foot","location":"the right side of the box","assist":"Nahuel Molina","assist_type":null,"stats_after":{"Barcelona":{"shots":12,"shots_on_target":3,"corners":2,"fouls":7,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":2,"shots_on_target":2,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 45);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-046', 'barca-atleti-2025-md19', 2, NULL, 3813, '53''', 'shot', 'detail', 'Barcelona', 'Raphinha', 'Chance for Barcelona: Raphinha''s left-footed shot from the left side of the box goes off target (set up by Lamine Yamal)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"the left side of the box","assist":"Lamine Yamal","assist_type":null,"stats_after":{"Barcelona":{"shots":13,"shots_on_target":3,"corners":2,"fouls":7,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":2,"shots_on_target":2,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 46);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-047', 'barca-atleti-2025-md19', 2, NULL, 3813, '53''', 'shot', 'key', 'Atlético de Madrid', 'Giuliano Simeone', 'Chance for Atlético de Madrid: Giuliano Simeone''s right-footed shot from the centre of the box goes off target (set up by Julián Alvarez)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the centre of the box","assist":"Julián Alvarez","assist_type":null,"stats_after":{"Barcelona":{"shots":13,"shots_on_target":3,"corners":2,"fouls":7,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 47);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-048', 'barca-atleti-2025-md19', 2, NULL, 3933, '55''', 'foul', 'detail', 'Barcelona', 'Lamine Yamal', 'Foul by Lamine Yamal (Barcelona) on Conor Gallagher; Atlético de Madrid get a free kick in the opponents'' half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Conor Gallagher","free_kick_for":"Atlético de Madrid","free_kick_zone":"in the opponents'' half","stats_after":{"Barcelona":{"shots":13,"shots_on_target":3,"corners":2,"fouls":8,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":7,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 48);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-049', 'barca-atleti-2025-md19', 2, NULL, 3993, '56''', 'foul', 'detail', 'Atlético de Madrid', 'José María Giménez', 'Foul by José María Giménez (Atlético de Madrid) on Alejandro Balde; Barcelona get a free kick in their own half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Alejandro Balde","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":13,"shots_on_target":3,"corners":2,"fouls":8,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 49);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-050', 'barca-atleti-2025-md19', 2, NULL, 4053, '57''', 'foul', 'detail', 'Barcelona', 'Robert Lewandowski', 'Foul by Robert Lewandowski (Barcelona) on Pablo Barrios; Atlético de Madrid get a free kick in the opponents'' half', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"victim":"Pablo Barrios","free_kick_for":"Atlético de Madrid","free_kick_zone":"in the opponents'' half","stats_after":{"Barcelona":{"shots":13,"shots_on_target":3,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 50);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-051', 'barca-atleti-2025-md19', 2, NULL, 4113, '58''', 'shot', 'detail', 'Barcelona', 'Dani Olmo', 'Chance for Barcelona: Dani Olmo''s right-footed shot from outside the box goes off target — over the bar (set up by Robert Lewandowski)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"outside the box","assist":"Robert Lewandowski","assist_type":null,"stats_after":{"Barcelona":{"shots":14,"shots_on_target":3,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 51);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-052', 'barca-atleti-2025-md19', 2, NULL, 4293, '61''', 'injury', 'detail', 'Atlético de Madrid', 'Álex Baena', 'Play stopped for treatment to Álex Baena (Atlético de Madrid)', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":14,"shots_on_target":3,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 52);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-053', 'barca-atleti-2025-md19', 2, NULL, 4353, '62''', 'substitution', 'key', 'Atlético de Madrid', 'Thiago Almada', 'Substitution, Atlético de Madrid: Thiago Almada comes on for Álex Baena (injury). Baena, the goalscorer, was also on a yellow card', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Thiago Almada","player_off":"Álex Baena","reason":"Injury","stats_after":{"Barcelona":{"shots":14,"shots_on_target":3,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 53);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-054', 'barca-atleti-2025-md19', 2, NULL, 4413, '63''', 'substitution', 'key', 'Atlético de Madrid', 'Alexander Sørloth', 'Substitution, Atlético de Madrid: Alexander Sørloth comes on for Giuliano Simeone', '{"Barcelona":1,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Alexander Sørloth","player_off":"Giuliano Simeone","reason":"Tactical","stats_after":{"Barcelona":{"shots":14,"shots_on_target":3,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 54);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-055', 'barca-atleti-2025-md19', 2, NULL, 4533, '65''', 'goal', 'key', 'Barcelona', 'Dani Olmo', 'GOAL! Dani Olmo scores for Barcelona — left foot from the centre of the box, into the bottom right corner. The finish ends a flowing team move; Olmo hurts his shoulder in the process. Score: Barcelona 2–1 Atlético de Madrid', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"body_part":"left foot","location":"the centre of the box","placement":"bottom right corner","assist":null,"assist_type":null,"penalty":false,"stats_after":{"Barcelona":{"shots":15,"shots_on_target":4,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 55);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-056', 'barca-atleti-2025-md19', 2, NULL, 4533, '65''', 'injury', 'detail', 'Barcelona', 'Dani Olmo', 'Play stopped for treatment to Dani Olmo (Barcelona). Shoulder problem after scoring', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":15,"shots_on_target":4,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 56);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-057', 'barca-atleti-2025-md19', 2, NULL, 4593, '66''', 'substitution', 'key', 'Barcelona', 'Marcus Rashford', 'Substitution, Barcelona: Marcus Rashford comes on for Dani Olmo (injury)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Marcus Rashford","player_off":"Dani Olmo","reason":"Injury","stats_after":{"Barcelona":{"shots":15,"shots_on_target":4,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 57);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-058', 'barca-atleti-2025-md19', 2, NULL, 4653, '67''', 'substitution', 'key', 'Barcelona', 'Ferran Torres', 'Substitution, Barcelona: Ferran Torres comes on for Robert Lewandowski', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Ferran Torres","player_off":"Robert Lewandowski","reason":"Tactical","stats_after":{"Barcelona":{"shots":15,"shots_on_target":4,"corners":2,"fouls":9,"offsides":0,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 58);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-059', 'barca-atleti-2025-md19', 2, NULL, 4713, '68''', 'offside', 'detail', 'Barcelona', 'Marcus Rashford', 'Offside: Marcus Rashford (Barcelona) is flagged offside', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":15,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 59);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-060', 'barca-atleti-2025-md19', 2, NULL, 4773, '69''', 'shot', 'detail', 'Barcelona', 'Lamine Yamal', 'Chance for Barcelona: Lamine Yamal''s left-footed shot from the right side of the box goes off target', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"the right side of the box","assist":null,"assist_type":null,"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 60);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-061', 'barca-atleti-2025-md19', 2, NULL, 4953, '72''', 'injury', 'detail', 'Barcelona', 'Pedri', 'Play stopped for treatment to Pedri (Barcelona)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 61);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-062', 'barca-atleti-2025-md19', 2, NULL, 5073, '74''', 'substitution', 'key', 'Barcelona', 'Dro Fernández', 'Substitution, Barcelona: Dro Fernández comes on for Raphinha', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Dro Fernández","player_off":"Raphinha","reason":"Tactical","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 62);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-063', 'barca-atleti-2025-md19', 2, NULL, 5073, '74''', 'substitution', 'key', 'Barcelona', 'Marc Casadó', 'Substitution, Barcelona: Marc Casadó comes on for Pedri (injury)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Marc Casadó","player_off":"Pedri","reason":"Injury","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":2,"yellow_cards":1}}}'::jsonb, true, 63);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-064', 'barca-atleti-2025-md19', 2, NULL, 5073, '74''', 'offside', 'detail', 'Atlético de Madrid', 'Conor Gallagher', 'Offside: Conor Gallagher (Atlético de Madrid) is flagged offside', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 64);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-065', 'barca-atleti-2025-md19', 2, NULL, 5133, '75''', 'substitution', 'key', 'Atlético de Madrid', 'Antoine Griezmann', 'Substitution, Atlético de Madrid: Antoine Griezmann comes on for Koke', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Antoine Griezmann","player_off":"Koke","reason":"Tactical","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 65);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-066', 'barca-atleti-2025-md19', 2, NULL, 5193, '76''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Clément Lenglet)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Clément Lenglet","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":3,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 66);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-067', 'barca-atleti-2025-md19', 2, NULL, 5253, '77''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Jan Oblak)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Jan Oblak","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":9,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 67);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-068', 'barca-atleti-2025-md19', 2, NULL, 5313, '78''', 'foul', 'detail', 'Barcelona', 'Eric García', 'Foul by Eric García (Barcelona) on Dávid Hancko; Atlético de Madrid get a free kick in their own half', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"victim":"Dávid Hancko","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":10,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":3,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 68);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-069', 'barca-atleti-2025-md19', 2, NULL, 5373, '79''', 'shot', 'key', 'Atlético de Madrid', 'Thiago Almada', 'Chance for Atlético de Madrid: Thiago Almada''s right-footed shot from the centre of the box goes off target — wide — he had beaten defenders inside the area and nearly equalised (set up by Dávid Hancko)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the centre of the box","assist":"Dávid Hancko","assist_type":null,"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":10,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":1,"fouls":8,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 69);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-070', 'barca-atleti-2025-md19', 2, NULL, 5613, '83''', 'foul', 'detail', 'Atlético de Madrid', 'Thiago Almada', 'Foul by Thiago Almada (Atlético de Madrid) on Dro Fernández; Barcelona get a free kick in their own half', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"victim":"Dro Fernández","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":10,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":1,"fouls":9,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 70);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-071', 'barca-atleti-2025-md19', 2, NULL, 5733, '85''', 'corner', 'detail', 'Atlético de Madrid', NULL, 'Corner to Atlético de Madrid (conceded by Gerard Martín)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Gerard Martín","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":10,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":2,"fouls":9,"offsides":3,"yellow_cards":1}}}'::jsonb, true, 71);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-072', 'barca-atleti-2025-md19', 2, NULL, 5793, '86''', 'offside', 'detail', 'Atlético de Madrid', 'Antoine Griezmann', 'Offside: Antoine Griezmann (Atlético de Madrid) is flagged offside', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":10,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":2,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 72);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-073', 'barca-atleti-2025-md19', 2, NULL, 5853, '87''', 'foul', 'detail', 'Barcelona', 'Marc Casadó', 'Foul by Marc Casadó (Barcelona) on Pablo Barrios; Atlético de Madrid get a free kick in the opponents'' half', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"victim":"Pablo Barrios","free_kick_for":"Atlético de Madrid","free_kick_zone":"in the opponents'' half","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":11,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":2,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 73);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-074', 'barca-atleti-2025-md19', 2, NULL, 5913, '88''', 'substitution', 'key', 'Barcelona', 'Andreas Christensen', 'Substitution, Barcelona: Andreas Christensen comes on for Lamine Yamal. A defender on for a forward to protect the lead', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"player_on":"Andreas Christensen","player_off":"Lamine Yamal","reason":"Tactical","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":11,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":2,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 74);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-075', 'barca-atleti-2025-md19', 2, NULL, 5973, '89''', 'foul', 'detail', 'Barcelona', 'Jules Koundé', 'Foul by Jules Koundé (Barcelona) on Julián Alvarez; Atlético de Madrid get a free kick in their own half', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"victim":"Julián Alvarez","free_kick_for":"Atlético de Madrid","free_kick_zone":"in their own half","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":4,"shots_on_target":2,"corners":2,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 75);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-076', 'barca-atleti-2025-md19', 2, NULL, 6033, '90''', 'shot', 'detail', 'Atlético de Madrid', 'Nahuel Molina', 'Chance for Atlético de Madrid: Nahuel Molina''s right-footed shot from outside the box is blocked by a defender', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":null,"assist_type":null,"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":5,"shots_on_target":2,"corners":2,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 76);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-077', 'barca-atleti-2025-md19', 2, NULL, 6033, '90''', 'corner', 'detail', 'Atlético de Madrid', NULL, 'Corner to Atlético de Madrid (conceded by Andreas Christensen)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Andreas Christensen","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":5,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 77);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-078', 'barca-atleti-2025-md19', 2, NULL, 6033, '90''', 'shot', 'detail', 'Atlético de Madrid', 'Dávid Hancko', 'Chance for Atlético de Madrid: Dávid Hancko''s header from the centre of the box goes off target — over the bar (set up by Julián Alvarez, with a cross)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Head","location":"the centre of the box","assist":"Julián Alvarez","assist_type":"with a cross","stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":6,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 78);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-079', 'barca-atleti-2025-md19', 2, NULL, 6033, '90''', 'added_time', 'detail', NULL, NULL, 'Fourth official signals 6 minutes of added time', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"minutes":6,"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":6,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 79);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-080', 'barca-atleti-2025-md19', 2, NULL, 6093, '90+1''', 'shot', 'key', 'Atlético de Madrid', 'Antoine Griezmann', 'Chance for Atlético de Madrid: Antoine Griezmann''s left-footed shot from the centre of the box goes off target (set up by Thiago Almada)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"the centre of the box","assist":"Thiago Almada","assist_type":null,"stats_after":{"Barcelona":{"shots":16,"shots_on_target":4,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 80);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-081', 'barca-atleti-2025-md19', 2, NULL, 6153, '90+2''', 'shot', 'key', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s left-footed shot from the left side of the box is saved — Oblak saves low to his left (set up by Marc Casadó)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"saved","body_part":"Left foot","location":"the left side of the box","assist":"Marc Casadó","assist_type":null,"stats_after":{"Barcelona":{"shots":17,"shots_on_target":5,"corners":4,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 81);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-082', 'barca-atleti-2025-md19', 2, NULL, 6153, '90+2''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Jan Oblak)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Jan Oblak","stats_after":{"Barcelona":{"shots":17,"shots_on_target":5,"corners":5,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 82);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-083', 'barca-atleti-2025-md19', 2, NULL, 6213, '90+3''', 'shot', 'detail', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s right-footed shot from outside the box goes off target — just wide (set up by Alejandro Balde)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"outside the box","assist":"Alejandro Balde","assist_type":null,"stats_after":{"Barcelona":{"shots":18,"shots_on_target":5,"corners":5,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":3,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 83);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-084', 'barca-atleti-2025-md19', 2, NULL, 6333, '90+5''', 'corner', 'detail', 'Atlético de Madrid', NULL, 'Corner to Atlético de Madrid (conceded by Gerard Martín)', '{"Barcelona":2,"Atlético de Madrid":1}'::jsonb, '{"conceded_by":"Gerard Martín","stats_after":{"Barcelona":{"shots":18,"shots_on_target":5,"corners":5,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":4,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 84);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-085', 'barca-atleti-2025-md19', 2, NULL, 6393, '90+6''', 'goal', 'key', 'Barcelona', 'Ferran Torres', 'GOAL! Ferran Torres scores for Barcelona — right foot from very close range, into the centre of the goal (assist: Alejandro Balde, with a cross). Torres was left unmarked in the box. Score: Barcelona 3–1 Atlético de Madrid', '{"Barcelona":3,"Atlético de Madrid":1}'::jsonb, '{"body_part":"right foot","location":"very close range","placement":"centre of the goal","assist":"Alejandro Balde","assist_type":"with a cross","penalty":false,"stats_after":{"Barcelona":{"shots":19,"shots_on_target":6,"corners":5,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":4,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 85);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('barati-086', 'barca-atleti-2025-md19', 2, NULL, 6453, '90+7''', 'period_end', 'key', NULL, NULL, 'Full time (6 minutes of added time were played)', '{"Barcelona":3,"Atlético de Madrid":1}'::jsonb, '{"added_minutes":6,"stats_after":{"Barcelona":{"shots":19,"shots_on_target":6,"corners":5,"fouls":12,"offsides":1,"yellow_cards":1},"Atlético de Madrid":{"shots":7,"shots_on_target":2,"corners":4,"fouls":9,"offsides":4,"yellow_cards":1}}}'::jsonb, true, 86);
INSERT INTO public.matches (id, mode, title, competition, youtube_id, config, sort_order)
VALUES ('betis-barca-2025-md15', 'replay', 'Real Betis vs Barcelona', 'LaLiga 2025/26 — Matchday 15', '93LPZJkCW2w', '{"id":"betis-barca-2025-md15","mode":"replay","title":"Real Betis vs Barcelona","competition":"LaLiga 2025/26 — Matchday 15","venue":"Estadio de La Cartuja, Seville","date":"2025-12-06","home":"Real Betis","away":"Barcelona","final_score":{"Real Betis":3,"Barcelona":5},"youtube_id":"93LPZJkCW2w","period_starts":{"1":353,"2":3463},"period_ends":{"1":3353,"2":6540},"period_base_minute":{"1":0,"2":45},"period_length_min":{"1":45,"2":45},"lineups":{"Real Betis":{"formation":"4-2-3-1","manager":"Manuel Pellegrini","starting_xi":["Álvaro Valles","Aitor Ruibal","Marc Bartra","Natan","Valentín Gómez","Marc Roca","Sergi Altimira","Antony","Pablo Fornals","Abde Ezzalzouli","Cucho Hernández"]},"Barcelona":{"formation":"4-2-3-1","manager":"Hansi Flick","starting_xi":["Joan García","Jules Koundé","Pau Cubarsí","Eric García","Gerard Martín","Alejandro Balde","Pedri","Lamine Yamal","Roony Bardghji","Marcus Rashford","Ferran Torres"],"notes":"Lamine Yamal played mostly in an interior, creative midfield role rather than on the right wing. Lewandowski and Raphinha stayed on the bench."}},"full_time_stats":{"possession":"37.8% – 62.2%","shots":"17 – 16","shots_on_target":"5 – 8","expected_goals":"2.52 – 2.60","corners":"7 – 7","fouls":"14 – 9","offsides":"6 – 1","yellow_cards":"4 – 2","penalties":"1 (1 scored) – 1 (1 scored)"},"referee":"Francisco José Hernández Maeso","events_file":"betis_barca_events.json","data_credit":"Event data compiled from LaLiga''s official minute-by-minute match record and published match reports; times accurate to the minute","teams":{"Real Betis":{"short":"BET","color":"#2FBF71","text":"#6FDC9E"},"Barcelona":{"short":"BAR","color":"#4C8DF6","text":"#8DB6FF"}}}'::jsonb, 1)
ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, sort_order = EXCLUDED.sort_order;
DELETE FROM public.match_events WHERE match_id = 'betis-barca-2025-md15';
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-001', 'betis-barca-2025-md15', 1, NULL, 353, '1''', 'period_start', 'key', NULL, NULL, 'Kick-off: 1st half begins', '{"Real Betis":0,"Barcelona":0}'::jsonb, '{"stats_after":{"Real Betis":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 1);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-002', 'betis-barca-2025-md15', 1, NULL, 413, '1''', 'foul', 'detail', 'Barcelona', 'Ferran Torres', 'Foul by Ferran Torres (Barcelona) on Antony; Real Betis get a free kick in their own half', '{"Real Betis":0,"Barcelona":0}'::jsonb, '{"victim":"Antony","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":0,"shots_on_target":0,"corners":0,"fouls":0,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 2);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-003', 'betis-barca-2025-md15', 1, NULL, 473, '2''', 'foul', 'detail', 'Real Betis', 'Aitor Ruibal', 'Foul by Aitor Ruibal (Real Betis) on Pedri; Barcelona get a free kick in their own half', '{"Real Betis":0,"Barcelona":0}'::jsonb, '{"victim":"Pedri","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0}}}'::jsonb, true, 3);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-004', 'betis-barca-2025-md15', 1, NULL, 653, '5''', 'offside', 'detail', 'Barcelona', 'Alejandro Balde', 'Offside: Alejandro Balde (Barcelona) is flagged offside', '{"Real Betis":0,"Barcelona":0}'::jsonb, '{"stats_after":{"Real Betis":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 4);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-005', 'betis-barca-2025-md15', 1, NULL, 713, '6''', 'shot', 'detail', 'Real Betis', 'Pablo Fornals', 'Chance for Real Betis: Pablo Fornals''s right-footed shot from the centre of the box is blocked by a defender (set up by Cucho Hernández)', '{"Real Betis":0,"Barcelona":0}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"the centre of the box","assist":"Cucho Hernández","assist_type":null,"stats_after":{"Real Betis":{"shots":1,"shots_on_target":0,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 5);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-006', 'betis-barca-2025-md15', 1, NULL, 713, '6''', 'goal', 'key', 'Real Betis', 'Antony', 'GOAL! Antony scores for Real Betis — right foot from the centre of the box, into the top right corner. He finishes after a goalmouth scramble of blocks and deflections. Score: Real Betis 1–0 Barcelona', '{"Real Betis":1,"Barcelona":0}'::jsonb, '{"body_part":"right foot","location":"the centre of the box","placement":"top right corner","assist":null,"assist_type":null,"penalty":false,"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":1,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 6);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-007', 'betis-barca-2025-md15', 1, NULL, 893, '9''', 'foul', 'detail', 'Real Betis', 'Valentín Gómez', 'Foul by Valentín Gómez (Real Betis) on Lamine Yamal; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":0}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":0,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 7);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-008', 'betis-barca-2025-md15', 1, NULL, 893, '9''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Valentín Gómez)', '{"Real Betis":1,"Barcelona":0}'::jsonb, '{"conceded_by":"Valentín Gómez","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":0,"shots_on_target":0,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 8);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-009', 'betis-barca-2025-md15', 1, NULL, 953, '10''', 'shot', 'key', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s left-footed shot from the left side of the box is saved — Valles saves low to his left', '{"Real Betis":1,"Barcelona":0}'::jsonb, '{"outcome":"saved","body_part":"Left foot","location":"the left side of the box","assist":null,"assist_type":null,"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":1,"shots_on_target":1,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 9);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-010', 'betis-barca-2025-md15', 1, NULL, 1013, '11''', 'goal', 'key', 'Barcelona', 'Ferran Torres', 'GOAL! Ferran Torres scores for Barcelona — right foot from the centre of the box, into the bottom right corner (assist: Jules Koundé). Torres slipped in behind the defensive line to finish Koundé''s pass. Score: Real Betis 1–1 Barcelona', '{"Real Betis":1,"Barcelona":1}'::jsonb, '{"body_part":"right foot","location":"the centre of the box","placement":"bottom right corner","assist":"Jules Koundé","assist_type":null,"penalty":false,"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":0,"yellow_cards":0},"Barcelona":{"shots":2,"shots_on_target":2,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 10);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-011', 'betis-barca-2025-md15', 1, NULL, 1133, '13''', 'offside', 'detail', 'Real Betis', 'Pablo Fornals', 'Offside: Pablo Fornals (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":1}'::jsonb, '{"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":2,"shots_on_target":2,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 11);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-012', 'betis-barca-2025-md15', 1, NULL, 1133, '13''', 'goal', 'key', 'Barcelona', 'Ferran Torres', 'GOAL! Ferran Torres scores for Barcelona — right foot from the centre of the box, into the centre of the goal (assist: Roony Bardghji, with a cross). A volley from Bardghji''s cross that went through goalkeeper Álvaro Valles'' legs. Score: Real Betis 1–2 Barcelona', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"body_part":"right foot","location":"the centre of the box","placement":"centre of the goal","assist":"Roony Bardghji","assist_type":"with a cross","penalty":false,"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":0,"fouls":2,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 12);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-013', 'betis-barca-2025-md15', 1, NULL, 1253, '15''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Gerard Martín)', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"conceded_by":"Gerard Martín","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":1,"fouls":2,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 13);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-014', 'betis-barca-2025-md15', 1, NULL, 1253, '15''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Jules Koundé)', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"conceded_by":"Jules Koundé","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":2,"fouls":2,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 14);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-015', 'betis-barca-2025-md15', 1, NULL, 1553, '20''', 'foul', 'detail', 'Real Betis', 'Sergi Altimira', 'Foul by Sergi Altimira (Real Betis) on Pedri; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"victim":"Pedri","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":2,"fouls":3,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 15);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-016', 'betis-barca-2025-md15', 1, NULL, 1613, '21''', 'foul', 'detail', 'Real Betis', 'Sergi Altimira', 'Foul by Sergi Altimira (Real Betis) on Lamine Yamal; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":0},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 16);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-017', 'betis-barca-2025-md15', 1, NULL, 1613, '21''', 'card', 'key', 'Real Betis', 'Sergi Altimira', 'YELLOW CARD: Sergi Altimira (Real Betis) is booked — a bad foul on Lamine Yamal. His second foul in two minutes', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"card":"Yellow Card","reason":"a bad foul on Lamine Yamal","is_manager":false,"stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":1,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 17);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-018', 'betis-barca-2025-md15', 1, NULL, 1673, '22''', 'foul', 'detail', 'Barcelona', 'Eric García', 'Foul by Eric García (Barcelona) on Marc Roca; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"victim":"Marc Roca","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":2,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 18);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-019', 'betis-barca-2025-md15', 1, NULL, 1733, '23''', 'shot', 'detail', 'Real Betis', 'Abde Ezzalzouli', 'Chance for Real Betis: Abde Ezzalzouli''s left-footed shot from the left side of the box goes off target (set up by Aitor Ruibal)', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"the left side of the box","assist":"Aitor Ruibal","assist_type":null,"stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":3,"shots_on_target":3,"corners":1,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 19);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-020', 'betis-barca-2025-md15', 1, NULL, 1733, '23''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Sergi Altimira)', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"conceded_by":"Sergi Altimira","stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":3,"shots_on_target":3,"corners":2,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 20);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-021', 'betis-barca-2025-md15', 1, NULL, 1853, '25''', 'shot', 'detail', 'Barcelona', 'Roony Bardghji', 'Chance for Barcelona: Roony Bardghji''s left-footed shot from the centre of the box goes off target', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"the centre of the box","assist":null,"assist_type":null,"stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":4,"shots_on_target":3,"corners":2,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 21);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-022', 'betis-barca-2025-md15', 1, NULL, 1853, '25''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Marc Bartra)', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"conceded_by":"Marc Bartra","stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":4,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":4,"shots_on_target":3,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 22);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-023', 'betis-barca-2025-md15', 1, NULL, 2153, '30''', 'foul', 'detail', 'Real Betis', 'Valentín Gómez', 'Foul by Valentín Gómez (Real Betis) on Lamine Yamal; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":2}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":5,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":4,"shots_on_target":3,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 23);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-024', 'betis-barca-2025-md15', 1, NULL, 2213, '31''', 'goal', 'key', 'Barcelona', 'Roony Bardghji', 'GOAL! Roony Bardghji scores for Barcelona — right foot from the right side of the box, into the top right corner (assist: Pedri). A powerful strike — his first goal for Barcelona. Score: Real Betis 1–3 Barcelona', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"body_part":"right foot","location":"the right side of the box","placement":"top right corner","assist":"Pedri","assist_type":null,"penalty":false,"stats_after":{"Real Betis":{"shots":3,"shots_on_target":1,"corners":2,"fouls":5,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":5,"shots_on_target":4,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 24);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-025', 'betis-barca-2025-md15', 1, NULL, 2333, '33''', 'shot', 'detail', 'Real Betis', 'Antony', 'Chance for Real Betis: Antony''s left-footed shot from outside the box is blocked by a defender', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"outcome":"blocked","body_part":"Left foot","location":"outside the box","assist":null,"assist_type":null,"stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":5,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":5,"shots_on_target":4,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 25);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-026', 'betis-barca-2025-md15', 1, NULL, 2393, '34''', 'foul', 'detail', 'Real Betis', 'Marc Roca', 'Foul by Marc Roca (Real Betis) on Lamine Yamal; Barcelona get a free kick in the opponents'' half', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in the opponents'' half","stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":5,"shots_on_target":4,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 26);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-027', 'betis-barca-2025-md15', 1, NULL, 2453, '35''', 'shot', 'detail', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s right-footed shot from outside the box is blocked by a defender', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":null,"assist_type":null,"stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":6,"shots_on_target":4,"corners":3,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 27);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-028', 'betis-barca-2025-md15', 1, NULL, 2453, '35''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Cucho Hernández)', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"conceded_by":"Cucho Hernández","stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":6,"shots_on_target":4,"corners":4,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 28);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-029', 'betis-barca-2025-md15', 1, NULL, 2633, '38''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Marc Bartra)', '{"Real Betis":1,"Barcelona":3}'::jsonb, '{"conceded_by":"Marc Bartra","stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":6,"shots_on_target":4,"corners":5,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 29);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-030', 'betis-barca-2025-md15', 1, NULL, 2753, '40''', 'goal', 'key', 'Barcelona', 'Ferran Torres', 'GOAL! Ferran Torres scores for Barcelona — right foot from outside the box, into the bottom right corner (assist: Pedri). Hat-trick for Torres; match reports say the shot took a deflection off a defender and wrong-footed Valles. Score: Real Betis 1–4 Barcelona', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"body_part":"right foot","location":"outside the box","placement":"bottom right corner","assist":"Pedri","assist_type":null,"penalty":false,"stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":7,"shots_on_target":5,"corners":5,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 30);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-031', 'betis-barca-2025-md15', 1, NULL, 2873, '42''', 'shot', 'key', 'Barcelona', 'Ferran Torres', 'Chance for Barcelona: Ferran Torres''s right-footed shot from the right side of the box is saved — Valles saves in the centre of the goal (set up by Lamine Yamal, with a through ball)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"saved","body_part":"Right foot","location":"the right side of the box","assist":"Lamine Yamal","assist_type":"with a through ball","stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 31);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-032', 'betis-barca-2025-md15', 1, NULL, 2873, '42''', 'injury', 'detail', 'Real Betis', 'Natan', 'Play stopped for treatment to Natan (Real Betis)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"stats_after":{"Real Betis":{"shots":4,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 32);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-033', 'betis-barca-2025-md15', 1, NULL, 3053, '45''', 'shot', 'detail', 'Real Betis', 'Sergi Altimira', 'Chance for Real Betis: Sergi Altimira''s left-footed shot from outside the box goes off target — high and wide (set up by Abde Ezzalzouli)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"off target","body_part":"Left foot","location":"outside the box","assist":"Abde Ezzalzouli","assist_type":null,"stats_after":{"Real Betis":{"shots":5,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":2,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 33);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-034', 'betis-barca-2025-md15', 1, NULL, 3053, '45''', 'foul', 'detail', 'Barcelona', 'Alejandro Balde', 'Foul by Alejandro Balde (Barcelona) on Antony; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Antony","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":5,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 34);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-035', 'betis-barca-2025-md15', 1, NULL, 3053, '45''', 'added_time', 'detail', NULL, NULL, 'Fourth official signals 5 minutes of added time', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"minutes":5,"stats_after":{"Real Betis":{"shots":5,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 35);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-036', 'betis-barca-2025-md15', 1, NULL, 3113, '45+1''', 'shot', 'key', 'Real Betis', 'Cucho Hernández', 'Chance for Real Betis: Cucho Hernández''s header from the centre of the box goes off target — just wide (set up by Aitor Ruibal, with a cross)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"off target","body_part":"Head","location":"the centre of the box","assist":"Aitor Ruibal","assist_type":"with a cross","stats_after":{"Real Betis":{"shots":6,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 36);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-037', 'betis-barca-2025-md15', 1, NULL, 3173, '45+2''', 'injury', 'detail', 'Barcelona', 'Jules Koundé', 'Play stopped for treatment to Jules Koundé (Barcelona)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"stats_after":{"Real Betis":{"shots":6,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 37);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-038', 'betis-barca-2025-md15', 1, NULL, 3293, '45+4''', 'shot', 'detail', 'Real Betis', 'Aitor Ruibal', 'Chance for Real Betis: Aitor Ruibal''s right-footed shot from the right side of the box goes off target — just wide (set up by Pablo Fornals)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":"Pablo Fornals","assist_type":null,"stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 38);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-039', 'betis-barca-2025-md15', 1, NULL, 3353, '45+5''', 'period_end', 'key', NULL, NULL, 'Half-time (5 minutes of added time were played)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"added_minutes":5,"stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 39);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-040', 'betis-barca-2025-md15', 2, NULL, 3463, '46''', 'substitution', 'key', 'Real Betis', 'Nelson Deossa', 'Substitution, Real Betis: Nelson Deossa comes on for Sergi Altimira. Altimira was on a yellow card', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"player_on":"Nelson Deossa","player_off":"Sergi Altimira","reason":"Tactical","stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 40);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-041', 'betis-barca-2025-md15', 2, NULL, 3463, '46''', 'substitution', 'key', 'Barcelona', 'Andreas Christensen', 'Substitution, Barcelona: Andreas Christensen comes on for Alejandro Balde', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"player_on":"Andreas Christensen","player_off":"Alejandro Balde","reason":"Tactical","stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 41);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-042', 'betis-barca-2025-md15', 2, NULL, 3463, '46''', 'period_start', 'key', NULL, NULL, '2nd half begins', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":6,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 42);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-043', 'betis-barca-2025-md15', 2, NULL, 3523, '46''', 'foul', 'detail', 'Real Betis', 'Nelson Deossa', 'Foul by Nelson Deossa (Real Betis) on Lamine Yamal; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":8,"shots_on_target":6,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 43);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-044', 'betis-barca-2025-md15', 2, NULL, 3583, '47''', 'shot', 'key', 'Barcelona', 'Ferran Torres', 'Chance for Barcelona: Ferran Torres''s header from the centre of the box is saved — Valles saves low to his left (set up by Jules Koundé, with a cross)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"saved","body_part":"Head","location":"the centre of the box","assist":"Jules Koundé","assist_type":"with a cross","stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":9,"shots_on_target":7,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 44);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-045', 'betis-barca-2025-md15', 2, NULL, 3583, '47''', 'shot', 'detail', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s right-footed shot from the right side of the box goes off target — wide, on a fast break', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":null,"assist_type":null,"stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":5,"fouls":3,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 45);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-046', 'betis-barca-2025-md15', 2, NULL, 3643, '48''', 'foul', 'detail', 'Barcelona', 'Gerard Martín', 'Foul by Gerard Martín (Barcelona) on Antony; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Antony","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":5,"fouls":4,"offsides":1,"yellow_cards":0}}}'::jsonb, true, 46);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-047', 'betis-barca-2025-md15', 2, NULL, 3643, '48''', 'card', 'key', 'Barcelona', 'Gerard Martín', 'YELLOW CARD: Gerard Martín (Barcelona) is booked — a bad foul on Antony', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"card":"Yellow Card","reason":"a bad foul on Antony","is_manager":false,"stats_after":{"Real Betis":{"shots":7,"shots_on_target":1,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":5,"fouls":4,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 47);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-048', 'betis-barca-2025-md15', 2, NULL, 3703, '49''', 'shot', 'key', 'Real Betis', 'Antony', 'Chance for Real Betis: Antony''s right-footed shot from the right side of the box is saved — Joan García saves low to his left (set up by Aitor Ruibal)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"saved","body_part":"Right foot","location":"the right side of the box","assist":"Aitor Ruibal","assist_type":null,"stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":5,"fouls":4,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 48);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-049', 'betis-barca-2025-md15', 2, NULL, 3763, '50''', 'foul', 'detail', 'Barcelona', 'Lamine Yamal', 'Foul by Lamine Yamal (Barcelona) on Abde Ezzalzouli; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Abde Ezzalzouli","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":5,"fouls":5,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 49);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-050', 'betis-barca-2025-md15', 2, NULL, 3823, '51''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Marc Bartra)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"conceded_by":"Marc Bartra","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":6,"fouls":5,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 50);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-051', 'betis-barca-2025-md15', 2, NULL, 3883, '52''', 'foul', 'detail', 'Barcelona', 'Jules Koundé', 'Foul by Jules Koundé (Barcelona) on Natan; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Natan","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":7,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 51);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-052', 'betis-barca-2025-md15', 2, NULL, 3943, '53''', 'foul', 'detail', 'Real Betis', 'Pablo Fornals', 'Foul by Pablo Fornals (Real Betis) on Eric García; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"victim":"Eric García","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":8,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":10,"shots_on_target":7,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 52);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-053', 'betis-barca-2025-md15', 2, NULL, 4003, '54''', 'shot', 'detail', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s right-footed shot from the left side of the box is blocked by a defender (set up by Gerard Martín)', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"the left side of the box","assist":"Gerard Martín","assist_type":null,"stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":8,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":11,"shots_on_target":7,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 53);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-054', 'betis-barca-2025-md15', 2, NULL, 4003, '54''', 'penalty_awarded', 'key', 'Real Betis', 'Marc Bartra', 'PENALTY to Barcelona: handball by Marc Bartra (Real Betis) inside the penalty area. Rashford''s shot struck Bartra''s arm; the decision went to a VAR review', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"offence":"Handball","victim":null,"penalty_for":"Barcelona","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":11,"shots_on_target":7,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 54);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-055', 'betis-barca-2025-md15', 2, NULL, 4183, '57''', 'var_decision', 'key', 'Barcelona', NULL, 'VAR decision: Penalty to Barcelona confirmed. After the review, the handball by Marc Bartra is given as a penalty', '{"Real Betis":1,"Barcelona":4}'::jsonb, '{"decision":"Penalty to Barcelona confirmed","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":11,"shots_on_target":7,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 55);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-056', 'betis-barca-2025-md15', 2, NULL, 4303, '59''', 'goal', 'key', 'Barcelona', 'Lamine Yamal', 'GOAL! Lamine Yamal scores the penalty for Barcelona (left foot, bottom left corner). Score: Real Betis 1–5 Barcelona', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"body_part":"left foot","location":null,"placement":"bottom left corner","assist":null,"assist_type":null,"penalty":true,"stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":1},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 56);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-057', 'betis-barca-2025-md15', 2, NULL, 4303, '59''', 'card', 'key', 'Real Betis', 'Nelson Deossa', 'YELLOW CARD: Nelson Deossa (Real Betis) is booked — dissent (arguing with the referee), according to match reports', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"card":"Yellow Card","reason":"dissent (arguing with the referee), according to match reports","is_manager":false,"stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 57);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-058', 'betis-barca-2025-md15', 2, NULL, 4363, '60''', 'substitution', 'key', 'Real Betis', 'Junior Firpo', 'Substitution, Real Betis: Junior Firpo comes on for Natan', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Junior Firpo","player_off":"Natan","reason":"Tactical","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 58);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-059', 'betis-barca-2025-md15', 2, NULL, 4363, '60''', 'substitution', 'key', 'Real Betis', 'Diego Llorente', 'Substitution, Real Betis: Diego Llorente comes on for Marc Bartra', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Diego Llorente","player_off":"Marc Bartra","reason":"Tactical","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":1,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 59);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-060', 'betis-barca-2025-md15', 2, NULL, 4423, '61''', 'offside', 'detail', 'Real Betis', 'Cucho Hernández', 'Offside: Cucho Hernández (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":2,"fouls":9,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 60);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-061', 'betis-barca-2025-md15', 2, NULL, 4483, '62''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Lamine Yamal)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"conceded_by":"Lamine Yamal","stats_after":{"Real Betis":{"shots":8,"shots_on_target":2,"corners":3,"fouls":9,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 61);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-062', 'betis-barca-2025-md15', 2, NULL, 4483, '62''', 'shot', 'detail', 'Real Betis', 'Cucho Hernández', 'Chance for Real Betis: Cucho Hernández''s right-footed shot from outside the box is blocked by a defender (set up by Antony)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":"Antony","assist_type":null,"stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":9,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 62);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-063', 'betis-barca-2025-md15', 2, NULL, 4483, '62''', 'foul', 'detail', 'Real Betis', 'Nelson Deossa', 'Foul by Nelson Deossa (Real Betis) on Lamine Yamal; Barcelona get a free kick in their own half', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"victim":"Lamine Yamal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 63);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-064', 'betis-barca-2025-md15', 2, NULL, 4543, '63''', 'substitution', 'key', 'Barcelona', 'Frenkie de Jong', 'Substitution, Barcelona: Frenkie de Jong comes on for Gerard Martín. Martín was on a yellow card', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Frenkie de Jong","player_off":"Gerard Martín","reason":"Tactical","stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 64);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-065', 'betis-barca-2025-md15', 2, NULL, 4543, '63''', 'substitution', 'key', 'Barcelona', 'Marc Bernal', 'Substitution, Barcelona: Marc Bernal comes on for Pedri', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Marc Bernal","player_off":"Pedri","reason":"Tactical","stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":12,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 65);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-066', 'betis-barca-2025-md15', 2, NULL, 4723, '66''', 'shot', 'detail', 'Barcelona', 'Roony Bardghji', 'Chance for Barcelona: Roony Bardghji''s right-footed shot from the right side of the box goes off target (set up by Lamine Yamal)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":"Lamine Yamal","assist_type":null,"stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":13,"shots_on_target":8,"corners":6,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 66);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-067', 'betis-barca-2025-md15', 2, NULL, 4723, '66''', 'corner', 'detail', 'Barcelona', NULL, 'Corner to Barcelona (conceded by Aitor Ruibal)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"conceded_by":"Aitor Ruibal","stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":2},"Barcelona":{"shots":13,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 67);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-068', 'betis-barca-2025-md15', 2, NULL, 4783, '67''', 'card', 'key', 'Real Betis', 'Aitor Ruibal', 'YELLOW CARD: Aitor Ruibal (Real Betis) is booked — a caution (the official record gives no reason)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"card":"Yellow Card","reason":"a caution (the official record gives no reason)","is_manager":false,"stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":3},"Barcelona":{"shots":13,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 68);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-069', 'betis-barca-2025-md15', 2, NULL, 4843, '68''', 'substitution', 'key', 'Barcelona', 'Fermín López', 'Substitution, Barcelona: Fermín López comes on for Roony Bardghji. Fermín returns after missing two games with a leg injury', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Fermín López","player_off":"Roony Bardghji","reason":"Tactical","stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":2,"yellow_cards":3},"Barcelona":{"shots":13,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 69);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-070', 'betis-barca-2025-md15', 2, NULL, 4903, '69''', 'offside', 'detail', 'Real Betis', 'Nelson Deossa', 'Offside: Nelson Deossa (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":3,"yellow_cards":3},"Barcelona":{"shots":13,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 70);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-071', 'betis-barca-2025-md15', 2, NULL, 4963, '70''', 'shot', 'detail', 'Barcelona', 'Fermín López', 'Chance for Barcelona: Fermín López''s right-footed shot from outside the box goes off target — high and wide (set up by Ferran Torres)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"outside the box","assist":"Ferran Torres","assist_type":null,"stats_after":{"Real Betis":{"shots":9,"shots_on_target":2,"corners":3,"fouls":10,"offsides":3,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 71);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-072', 'betis-barca-2025-md15', 2, NULL, 5023, '71''', 'shot', 'detail', 'Real Betis', 'Abde Ezzalzouli', 'Chance for Real Betis: Abde Ezzalzouli''s right-footed shot from the left side of the box is blocked by a defender (set up by Marc Roca)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"the left side of the box","assist":"Marc Roca","assist_type":null,"stats_after":{"Real Betis":{"shots":10,"shots_on_target":2,"corners":3,"fouls":10,"offsides":3,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 72);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-073', 'betis-barca-2025-md15', 2, NULL, 5023, '71''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Jules Koundé)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"conceded_by":"Jules Koundé","stats_after":{"Real Betis":{"shots":10,"shots_on_target":2,"corners":4,"fouls":10,"offsides":3,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 73);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-074', 'betis-barca-2025-md15', 2, NULL, 5083, '72''', 'shot', 'key', 'Real Betis', 'Antony', 'Chance for Real Betis: Antony''s left-footed shot from the right side of the box is saved — Joan García saves low to his left (set up by Abde Ezzalzouli)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"saved","body_part":"Left foot","location":"the right side of the box","assist":"Abde Ezzalzouli","assist_type":null,"stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":3,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 74);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-075', 'betis-barca-2025-md15', 2, NULL, 5203, '74''', 'offside', 'detail', 'Real Betis', 'Pablo Fornals', 'Offside: Pablo Fornals (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":4,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 75);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-076', 'betis-barca-2025-md15', 2, NULL, 5263, '75''', 'substitution', 'key', 'Real Betis', 'Pablo García', 'Substitution, Real Betis: Pablo García comes on for Antony', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Pablo García","player_off":"Antony","reason":"Tactical","stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":4,"yellow_cards":3},"Barcelona":{"shots":14,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 76);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-077', 'betis-barca-2025-md15', 2, NULL, 5383, '77''', 'shot', 'detail', 'Barcelona', 'Fermín López', 'Chance for Barcelona: Fermín López''s right-footed shot from the right side of the box goes off target (set up by Lamine Yamal)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":"Lamine Yamal","assist_type":null,"stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":4,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":6,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 77);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-078', 'betis-barca-2025-md15', 2, NULL, 5443, '78''', 'foul', 'detail', 'Barcelona', 'Eric García', 'Foul by Eric García (Barcelona) on Pablo García; Real Betis get a free kick in their own half', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"victim":"Pablo García","free_kick_for":"Real Betis","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":4,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 78);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-079', 'betis-barca-2025-md15', 2, NULL, 5503, '79''', 'offside', 'detail', 'Real Betis', 'Cucho Hernández', 'Offside: Cucho Hernández (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":5,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 79);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-080', 'betis-barca-2025-md15', 2, NULL, 5623, '81''', 'substitution', 'key', 'Barcelona', 'Jofre Torrents', 'Substitution, Barcelona: Jofre Torrents comes on for Eric García (injury)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"player_on":"Jofre Torrents","player_off":"Eric García","reason":"Injury","stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":5,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 80);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-081', 'betis-barca-2025-md15', 2, NULL, 5683, '82''', 'offside', 'detail', 'Real Betis', 'Pablo García', 'Offside: Pablo García (Real Betis) is flagged offside', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":10,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 81);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-082', 'betis-barca-2025-md15', 2, NULL, 5683, '82''', 'foul', 'detail', 'Real Betis', 'Nelson Deossa', 'Foul by Nelson Deossa (Real Betis) on Frenkie de Jong; Barcelona get a free kick in the opponents'' half', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"victim":"Frenkie de Jong","free_kick_for":"Barcelona","free_kick_zone":"in the opponents'' half","stats_after":{"Real Betis":{"shots":11,"shots_on_target":3,"corners":4,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 82);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-083', 'betis-barca-2025-md15', 2, NULL, 5683, '82''', 'shot', 'detail', 'Real Betis', 'Abde Ezzalzouli', 'Chance for Real Betis: Abde Ezzalzouli''s right-footed shot from outside the box is blocked by a defender (set up by Pablo Fornals)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"blocked","body_part":"Right foot","location":"outside the box","assist":"Pablo Fornals","assist_type":null,"stats_after":{"Real Betis":{"shots":12,"shots_on_target":3,"corners":4,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 83);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-084', 'betis-barca-2025-md15', 2, NULL, 5743, '83''', 'shot', 'detail', 'Real Betis', 'Aitor Ruibal', 'Chance for Real Betis: Aitor Ruibal''s right-footed shot from the right side of the box goes off target (set up by Pablo García)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":"Pablo García","assist_type":null,"stats_after":{"Real Betis":{"shots":13,"shots_on_target":3,"corners":4,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 84);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-085', 'betis-barca-2025-md15', 2, NULL, 5803, '84''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Andreas Christensen)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"conceded_by":"Andreas Christensen","stats_after":{"Real Betis":{"shots":13,"shots_on_target":3,"corners":5,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 85);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-086', 'betis-barca-2025-md15', 2, NULL, 5803, '84''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Marcus Rashford)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"conceded_by":"Marcus Rashford","stats_after":{"Real Betis":{"shots":13,"shots_on_target":3,"corners":6,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 86);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-087', 'betis-barca-2025-md15', 2, NULL, 5863, '85''', 'shot', 'detail', 'Real Betis', 'Abde Ezzalzouli', 'Chance for Real Betis: Abde Ezzalzouli''s header from very close range goes off target — just wide (set up by Pablo Fornals, with a cross from a corner)', '{"Real Betis":1,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Head","location":"very close range","assist":"Pablo Fornals","assist_type":"with a cross from a corner","stats_after":{"Real Betis":{"shots":14,"shots_on_target":3,"corners":6,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 87);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-088', 'betis-barca-2025-md15', 2, NULL, 5863, '85''', 'goal', 'key', 'Real Betis', 'Diego Llorente', 'GOAL! Diego Llorente scores for Real Betis — right foot from very close range, into the bottom right corner (assist: Abde Ezzalzouli, following a corner). Score: Real Betis 2–5 Barcelona', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"body_part":"right foot","location":"very close range","placement":"bottom right corner","assist":"Abde Ezzalzouli","assist_type":"following a corner","penalty":false,"stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":15,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 88);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-089', 'betis-barca-2025-md15', 2, NULL, 5923, '86''', 'shot', 'key', 'Barcelona', 'Marcus Rashford', 'Chance for Barcelona: Marcus Rashford''s right-footed shot from the right side of the box goes off target (set up by Frenkie de Jong, with a through ball)', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Right foot","location":"the right side of the box","assist":"Frenkie de Jong","assist_type":"with a through ball","stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":11,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 89);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-090', 'betis-barca-2025-md15', 2, NULL, 5983, '87''', 'foul', 'detail', 'Real Betis', 'Valentín Gómez', 'Foul by Valentín Gómez (Real Betis) on Marc Bernal; Barcelona get a free kick in their own half', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"victim":"Marc Bernal","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":3},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 90);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-091', 'betis-barca-2025-md15', 2, NULL, 5983, '87''', 'card', 'key', 'Real Betis', 'Valentín Gómez', 'YELLOW CARD: Valentín Gómez (Real Betis) is booked — a bad foul on Marc Bernal', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"card":"Yellow Card","reason":"a bad foul on Marc Bernal","is_manager":false,"stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 91);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-092', 'betis-barca-2025-md15', 2, NULL, 6043, '88''', 'injury', 'detail', 'Real Betis', 'Junior Firpo', 'Play stopped for treatment to Junior Firpo (Real Betis)', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 92);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-093', 'betis-barca-2025-md15', 2, NULL, 6043, '88''', 'card', 'key', 'Real Betis', 'Manuel Pellegrini', 'YELLOW CARD: Manuel Pellegrini (Real Betis, manager) is booked — protesting from the touchline', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"card":"Yellow Card","reason":"protesting from the touchline","is_manager":true,"stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 93);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-094', 'betis-barca-2025-md15', 2, NULL, 6103, '89''', 'substitution', 'key', 'Real Betis', 'Ricardo Rodríguez', 'Substitution, Real Betis: Ricardo Rodríguez comes on for Junior Firpo (injury)', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"player_on":"Ricardo Rodríguez","player_off":"Junior Firpo","reason":"Injury","stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":7,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 94);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-095', 'betis-barca-2025-md15', 2, NULL, 6163, '90''', 'penalty_awarded', 'key', 'Barcelona', 'Jules Koundé', 'PENALTY to Real Betis: Jules Koundé (Barcelona) fouls Abde Ezzalzouli inside the penalty area', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"offence":"Foul","victim":"Abde Ezzalzouli","penalty_for":"Real Betis","stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":1}}}'::jsonb, true, 95);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-096', 'betis-barca-2025-md15', 2, NULL, 6163, '90''', 'card', 'key', 'Barcelona', 'Jules Koundé', 'YELLOW CARD: Jules Koundé (Barcelona) is booked — the foul on Abde Ezzalzouli that gave away the penalty', '{"Real Betis":2,"Barcelona":5}'::jsonb, '{"card":"Yellow Card","reason":"the foul on Abde Ezzalzouli that gave away the penalty","is_manager":false,"stats_after":{"Real Betis":{"shots":15,"shots_on_target":4,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 96);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-097', 'betis-barca-2025-md15', 2, NULL, 6163, '90''', 'goal', 'key', 'Real Betis', 'Cucho Hernández', 'GOAL! Cucho Hernández scores the penalty for Real Betis (right foot, centre of the goal). Score: Real Betis 3–5 Barcelona', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"body_part":"right foot","location":null,"placement":"centre of the goal","assist":null,"assist_type":null,"penalty":true,"stats_after":{"Real Betis":{"shots":16,"shots_on_target":5,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 97);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-098', 'betis-barca-2025-md15', 2, NULL, 6163, '90''', 'added_time', 'detail', NULL, NULL, 'Fourth official signals 6 minutes of added time', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"minutes":6,"stats_after":{"Real Betis":{"shots":16,"shots_on_target":5,"corners":6,"fouls":12,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 98);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-099', 'betis-barca-2025-md15', 2, NULL, 6223, '90+1''', 'foul', 'detail', 'Real Betis', 'Pablo Fornals', 'Foul by Pablo Fornals (Real Betis) on Pau Cubarsí; Barcelona get a free kick in their own half', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"victim":"Pau Cubarsí","free_kick_for":"Barcelona","free_kick_zone":"in their own half","stats_after":{"Real Betis":{"shots":16,"shots_on_target":5,"corners":6,"fouls":13,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 99);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-100', 'betis-barca-2025-md15', 2, NULL, 6283, '90+2''', 'corner', 'detail', 'Real Betis', NULL, 'Corner to Real Betis (conceded by Frenkie de Jong)', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"conceded_by":"Frenkie de Jong","stats_after":{"Real Betis":{"shots":16,"shots_on_target":5,"corners":7,"fouls":13,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 100);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-101', 'betis-barca-2025-md15', 2, NULL, 6343, '90+3''', 'shot', 'detail', 'Real Betis', 'Abde Ezzalzouli', 'Chance for Real Betis: Abde Ezzalzouli''s header from the centre of the box goes off target — over the bar (set up by Pablo Fornals, with a cross from a corner)', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"outcome":"off target","body_part":"Head","location":"the centre of the box","assist":"Pablo Fornals","assist_type":"with a cross from a corner","stats_after":{"Real Betis":{"shots":17,"shots_on_target":5,"corners":7,"fouls":13,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 101);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-102', 'betis-barca-2025-md15', 2, NULL, 6403, '90+4''', 'foul', 'detail', 'Real Betis', 'Valentín Gómez', 'Foul by Valentín Gómez (Real Betis) on Marcus Rashford; Barcelona get a free kick on the left wing', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"victim":"Marcus Rashford","free_kick_for":"Barcelona","free_kick_zone":"on the left wing","stats_after":{"Real Betis":{"shots":17,"shots_on_target":5,"corners":7,"fouls":14,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":8,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 102);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-103', 'betis-barca-2025-md15', 2, NULL, 6463, '90+5''', 'foul', 'detail', 'Barcelona', 'Lamine Yamal', 'Foul by Lamine Yamal (Barcelona) on Abde Ezzalzouli; Real Betis get a free kick on the left wing', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"victim":"Abde Ezzalzouli","free_kick_for":"Real Betis","free_kick_zone":"on the left wing","stats_after":{"Real Betis":{"shots":17,"shots_on_target":5,"corners":7,"fouls":14,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":9,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 103);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('betbar-104', 'betis-barca-2025-md15', 2, NULL, 6523, '90+6''', 'period_end', 'key', NULL, NULL, 'Full time (6 minutes of added time were played)', '{"Real Betis":3,"Barcelona":5}'::jsonb, '{"added_minutes":6,"stats_after":{"Real Betis":{"shots":17,"shots_on_target":5,"corners":7,"fouls":14,"offsides":6,"yellow_cards":4},"Barcelona":{"shots":16,"shots_on_target":8,"corners":7,"fouls":9,"offsides":1,"yellow_cards":2}}}'::jsonb, true, 104);
INSERT INTO public.matches (id, mode, title, competition, youtube_id, config, sort_order)
VALUES ('arg-fra-2022-final', 'live', 'Argentina vs France', 'FIFA World Cup 2022 — Final', 'RgqKdplLIk4', '{"id":"arg-fra-2022-final","mode":"live","title":"Argentina vs France","competition":"FIFA World Cup 2022 — Final","venue":"Lusail Stadium, Lusail","home":"Argentina","away":"France","youtube_id":"RgqKdplLIk4","period_starts":{"1":96,"2":3296,"3":6604,"4":7613,"5":8838},"period_ends":{"1":3250,"2":6513,"3":7568,"4":8760,"5":9196},"period_base_minute":{"1":0,"2":45,"3":90,"4":105},"period_length_min":{"1":45,"2":45,"3":15,"4":15},"loop":{"start":96,"end":9229},"lineups":{"Argentina":{"formation":"4-3-3","starting_xi":["Emiliano Martínez (Goalkeeper)","Nahuel Molina (Right Back)","Cristian Romero (Right Center Back)","Nicolás Otamendi (Left Center Back)","Nicolás Tagliafico (Left Back)","Enzo Fernandez (Center Defensive Midfield)","Rodrigo De Paul (Right Center Midfield)","Alexis Mac Allister (Left Center Midfield)","Lionel Messi (Right Wing)","Ángel Di María (Left Wing)","Julián Álvarez (Center Forward)"]},"France":{"formation":"4-2-3-1","starting_xi":["Hugo Lloris (Goalkeeper)","Jules Koundé (Right Back)","Raphaël Varane (Right Center Back)","Dayotchanculle Upamecano (Left Center Back)","Theo Hernández (Left Back)","Aurélien Tchouaméni (Right Defensive Midfield)","Adrien Rabiot (Left Defensive Midfield)","Ousmane Dembélé (Right Wing)","Antoine Griezmann (Center Attacking Midfield)","Kylian Mbappé (Left Wing)","Olivier Giroud (Center Forward)"]}},"events_file":"arg_fra_events.json","data_credit":"Event data: StatsBomb Open Data (free for non-commercial use)","teams":{"Argentina":{"short":"ARG","color":"#7CC4F4","text":"#A4D8FA"},"France":{"short":"FRA","color":"#5B6CF5","text":"#9AA6FF"}},"listed":false}'::jsonb, 2)
ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, sort_order = EXCLUDED.sort_order;
DELETE FROM public.match_events WHERE match_id = 'arg-fra-2022-final';
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6404a8e8-afaf-489d-b65e-173a237ffed5', 'arg-fra-2022-final', 1, 0, 96, '1''', 'period_start', 'key', NULL, NULL, '1st half begins', '{"Argentina":0,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8932a9c2-693a-4dde-afad-5115c7237e87', 'arg-fra-2022-final', 1, 19, 115, '1''', 'foul', 'detail', 'France', 'Adrien Rabiot', 'Foul by Adrien Rabiot (France) on Rodrigo De Paul, attacking third', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('af7e1034-cf84-454b-bcad-7e8b8435d7b3', 'arg-fra-2022-final', 1, 49.2, 145.2, '1''', 'foul', 'detail', 'France', 'Aurélien Tchouaméni', 'Foul by Aurélien Tchouaméni (France) on Alexis Mac Allister, midfield', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Alexis Mac Allister","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('030b26ca-10a3-4d79-adfe-e8abe1762d07', 'arg-fra-2022-final', 1, 96.6, 192.6, '2''', 'foul', 'detail', 'Argentina', 'Rodrigo De Paul', 'Foul by Rodrigo De Paul (Argentina) on Adrien Rabiot, midfield', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Adrien Rabiot","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('25548b02-1dca-44b0-a1a5-d97f63a69fbd', 'arg-fra-2022-final', 1, 148.6, 244.6, '3''', 'offside', 'detail', 'Argentina', 'Julián Álvarez', 'Offside: Rodrigo De Paul (Argentina) passes forward but Julián Álvarez is caught offside', '{"Argentina":0,"France":0}'::jsonb, '{"passer":"Rodrigo De Paul"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('76e5ad79-f6cc-4769-96f4-6f8d2885347e', 'arg-fra-2022-final', 1, 193.6, 289.6, '4''', 'foul', 'detail', 'France', 'Dayotchanculle Upamecano', 'Foul by Dayotchanculle Upamecano (France) on Lionel Messi, midfield', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Lionel Messi","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('545c2c84-018f-4570-a01c-753823feaeac', 'arg-fra-2022-final', 1, 280.8, 376.8, '5''', 'shot', 'detail', 'Argentina', 'Alexis Mac Allister', 'Alexis Mac Allister (Argentina) shot — saved, set up by Julián Álvarez (xG 0.02)', '{"Argentina":0,"France":0}'::jsonb, '{"xg":0.02,"outcome":"Saved","shot_type":"Open Play","body_part":"Right Foot","assist":"Julián Álvarez","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b74c24d6-a0f1-42c4-b216-0b7a54e7834a', 'arg-fra-2022-final', 1, 344.8, 440.8, '6''', 'foul', 'detail', 'Argentina', 'Lionel Messi', 'Foul by Lionel Messi (Argentina) on Theo Hernández, midfield', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Theo Hernández","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e03bf54e-7bb7-4de0-bc65-05a64f58f25a', 'arg-fra-2022-final', 1, 402.3, 498.3, '7''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Adrien Rabiot, midfield', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Adrien Rabiot","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('4ad26294-8aaf-4d69-83dd-bbf9ef797b32', 'arg-fra-2022-final', 1, 456.5, 552.5, '8''', 'shot', 'detail', 'Argentina', 'Rodrigo De Paul', 'Rodrigo De Paul (Argentina) shot — blocked, set up by Ángel Di María (xG 0.06)', '{"Argentina":0,"France":0}'::jsonb, '{"xg":0.06,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":"Ángel Di María","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b134736d-422a-4c36-8e40-0b6962b8c5ac', 'arg-fra-2022-final', 1, 521.2, 617.2, '9''', 'foul', 'detail', 'Argentina', 'Cristian Romero', 'Foul by Cristian Romero (Argentina) on Hugo Lloris, inside the opponents'' penalty area', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Hugo Lloris","advantage":false,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('f00c9960-89c8-4cfc-b1d3-056834dc7cca', 'arg-fra-2022-final', 1, 528.8, 624.8, '9''', 'injury', 'detail', 'France', 'Hugo Lloris', 'Play stopped for an injury to Hugo Lloris (France)', '{"Argentina":0,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e5a4e3e0-5f09-4169-8acc-cba724138019', 'arg-fra-2022-final', 1, 565.5, 661.5, '10''', 'injury', 'detail', 'Argentina', 'Emiliano Martínez', 'Play stopped for an injury to Emiliano Martínez (Argentina)', '{"Argentina":0,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('cdf432a6-8394-4a1c-a454-3cb6a1d0a416', 'arg-fra-2022-final', 1, 725.7, 821.7, '13''', 'handball', 'detail', 'Argentina', 'Julián Álvarez', 'Handball by Julián Álvarez (Argentina), inside the opponents'' penalty area', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":"Handball","penalty":false,"victim":null,"advantage":false,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('2a0ff535-d44f-4838-a372-140631fb6184', 'arg-fra-2022-final', 1, 833.5, 929.5, '14''', 'offside', 'detail', 'Argentina', 'Ángel Di María', 'Offside: Nicolás Tagliafico (Argentina) passes forward but Ángel Di María is caught offside', '{"Argentina":0,"France":0}'::jsonb, '{"passer":"Nicolás Tagliafico"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6d498191-05f0-432c-8764-03aea4ef9fb8', 'arg-fra-2022-final', 1, 975.9, 1071.9, '17''', 'shot', 'detail', 'Argentina', 'Ángel Di María', 'Ángel Di María (Argentina) shot — off target (xG 0.11)', '{"Argentina":0,"France":0}'::jsonb, '{"xg":0.11,"outcome":"Off T","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('01d0ceb3-a2e3-4aee-9b65-d5d0d2f36706', 'arg-fra-2022-final', 1, 1091.8, 1187.8, '19''', 'foul', 'detail', 'Argentina', 'Rodrigo De Paul', 'Foul by Rodrigo De Paul (Argentina) on Theo Hernández, defensive third', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Theo Hernández","advantage":false,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('871be616-aa1d-4393-b8e0-54b7d3504966', 'arg-fra-2022-final', 1, 1143.2, 1239.2, '20''', 'foul', 'detail', 'France', 'Olivier Giroud', 'Foul by Olivier Giroud (France) on Ángel Di María, inside the opponents'' penalty area', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Ángel Di María","advantage":false,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('17cf2f79-db23-48fc-a33c-6969a54dd387', 'arg-fra-2022-final', 1, 1253.7, 1349.7, '21''', 'penalty_awarded', 'key', 'France', 'Ousmane Dembélé', 'Foul by Ousmane Dembélé (France) on Ángel Di María, inside France''s own penalty area — PENALTY to Argentina', '{"Argentina":0,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":true,"victim":"Ángel Di María","advantage":false,"zone":"inside France''s own penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6d527ebc-a948-4cd8-ac82-daced35bb715', 'arg-fra-2022-final', 1, 1344.1, 1440.1, '23''', 'goal', 'key', 'Argentina', 'Lionel Messi', 'GOAL! Lionel Messi scores for Argentina (penalty). Argentina 1–0 France', '{"Argentina":1,"France":0}'::jsonb, '{"xg":0.78,"shot_type":"Penalty","body_part":"Left Foot","assist":null}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e01f4dce-7585-4868-a780-071ef3b7b60f', 'arg-fra-2022-final', 1, 1532.5, 1628.5, '26''', 'foul', 'detail', 'Argentina', 'Cristian Romero', 'Foul by Cristian Romero (Argentina) on Olivier Giroud, defensive third', '{"Argentina":1,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Olivier Giroud","advantage":false,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b5e4c67b-be1f-4dee-a283-059f81a5cbed', 'arg-fra-2022-final', 1, 1612.1, 1708.1, '27''', 'foul', 'detail', 'France', 'Theo Hernández', 'Foul by Theo Hernández (France) on Lionel Messi, attacking third', '{"Argentina":1,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Lionel Messi","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('417f8e9c-a274-4977-82bc-a395452a9721', 'arg-fra-2022-final', 1, 1620.8, 1716.8, '28''', 'injury', 'detail', 'France', 'Theo Hernández', 'Play stopped for an injury to Theo Hernández (France)', '{"Argentina":1,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e53eb678-359a-45bc-8487-5b01071ceaac', 'arg-fra-2022-final', 1, 1630, 1726, '28''', 'injury', 'detail', 'Argentina', 'Lionel Messi', 'Play stopped for an injury to Lionel Messi (Argentina)', '{"Argentina":1,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d49e9601-1cbf-4df7-9a77-16877abe49dc', 'arg-fra-2022-final', 1, 1746.8, 1842.8, '30''', 'offside', 'detail', 'Argentina', 'Lionel Messi', 'Offside: Lionel Messi (Argentina) flagged offside', '{"Argentina":1,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('f227a92e-d86c-4f3d-aa75-5ccb71adcae6', 'arg-fra-2022-final', 1, 1895.2, 1991.2, '32''', 'shot', 'detail', 'Argentina', 'Alexis Mac Allister', 'Alexis Mac Allister (Argentina) shot — wayward, set up by Nicolás Tagliafico (xG 0.01)', '{"Argentina":1,"France":0}'::jsonb, '{"xg":0.01,"outcome":"Wayward","shot_type":"Open Play","body_part":"Right Foot","assist":"Nicolás Tagliafico","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('ef86f4d9-7acd-4ed0-a5ec-9129079e8fbe', 'arg-fra-2022-final', 1, 2122.6, 2218.6, '36''', 'goal', 'key', 'Argentina', 'Ángel Di María', 'GOAL! Ángel Di María scores for Argentina (left foot shot, assisted by Alexis Mac Allister). Argentina 2–0 France', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.3,"shot_type":"Open Play","body_part":"Left Foot","assist":"Alexis Mac Allister"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('9fea3c7a-e5aa-422e-9b39-f1ac9a66fcab', 'arg-fra-2022-final', 1, 2229.1, 2325.1, '38''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Aurélien Tchouaméni, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Aurélien Tchouaméni","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b43da17b-3459-43ed-b2c5-65c94a03f78c', 'arg-fra-2022-final', 1, 2271.7, 2367.7, '38''', 'foul', 'detail', 'France', 'Jules Koundé', 'Foul by Jules Koundé (France) on Alexis Mac Allister, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Alexis Mac Allister","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8a089b30-1eb8-42e6-9663-7bbc30ce2b70', 'arg-fra-2022-final', 1, 2411.6, 2507.6, '41''', 'foul', 'detail', 'France', 'Jules Koundé', 'Foul by Jules Koundé (France) on Ángel Di María, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Ángel Di María","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('df245155-92fc-4123-8bcf-66ba2ee77870', 'arg-fra-2022-final', 1, 2432.6, 2528.6, '41''', 'substitution', 'key', 'France', 'Randal Kolo Muani', 'Substitution France: Randal Kolo Muani ON, Ousmane Dembélé OFF (tactical change)', '{"Argentina":2,"France":0}'::jsonb, '{"player_on":"Randal Kolo Muani","player_off":"Ousmane Dembélé","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('bae6c6ee-59b6-419e-992d-7567437736f5', 'arg-fra-2022-final', 1, 2461.5, 2557.5, '42''', 'substitution', 'key', 'France', 'Marcus Thuram', 'Substitution France: Marcus Thuram ON, Olivier Giroud OFF (tactical change)', '{"Argentina":2,"France":0}'::jsonb, '{"player_on":"Marcus Thuram","player_off":"Olivier Giroud","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6452687c-5e26-4eb7-b996-38a785828030', 'arg-fra-2022-final', 1, 2472.2, 2568.2, '42''', 'foul', 'detail', 'France', 'Randal Kolo Muani', 'Foul by Randal Kolo Muani (France) on Nicolás Tagliafico, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Nicolás Tagliafico","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('776e2bb6-b9d4-4455-8965-d7c86afa4ad4', 'arg-fra-2022-final', 1, 2480.1, 2576.1, '42''', 'tactical_shift', 'detail', 'France', NULL, 'France change shape to 4-2-3-1', '{"Argentina":2,"France":0}'::jsonb, '{"formation":"4-2-3-1","lineup":["Hugo Lloris (Goalkeeper)","Jules Koundé (Right Back)","Raphaël Varane (Right Center Back)","Dayotchanculle Upamecano (Left Center Back)","Theo Hernández (Left Back)","Aurélien Tchouaméni (Right Defensive Midfield)","Adrien Rabiot (Left Defensive Midfield)","Randal Kolo Muani (Right Wing)","Antoine Griezmann (Center Attacking Midfield)","Marcus Thuram (Left Wing)","Kylian Mbappé (Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('4a5e7982-23bb-4078-a8c3-40ddd4dd27fd', 'arg-fra-2022-final', 1, 2499.5, 2595.5, '42''', 'foul', 'detail', 'France', 'Randal Kolo Muani', 'Foul by Randal Kolo Muani (France) on Nicolás Tagliafico, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Nicolás Tagliafico","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('dd1f7023-c1a3-496a-9a32-a7f91fc2b53c', 'arg-fra-2022-final', 1, 2648.4, 2744.4, '45''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Theo Hernández, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Theo Hernández","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('db38e34b-9d5e-4773-9c49-bc37b3d97c4e', 'arg-fra-2022-final', 1, 2794.1, 2890.1, '45+2''', 'foul', 'detail', 'France', 'Theo Hernández', 'Foul by Theo Hernández (France) on Rodrigo De Paul, attacking third', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('af8c7775-091a-4905-aeb3-484b9a99de81', 'arg-fra-2022-final', 1, 3081.1, 3177.1, '45+7''', 'card', 'key', 'Argentina', 'Enzo Fernandez', 'Foul by Enzo Fernandez (Argentina) on Randal Kolo Muani, midfield — YELLOW CARD for Enzo Fernandez', '{"Argentina":2,"France":0}'::jsonb, '{"card":"Yellow Card","foul_type":null,"penalty":false,"victim":"Randal Kolo Muani","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('595f7a7f-5d24-4f99-b4e8-bacaeaa2de17', 'arg-fra-2022-final', 1, 3154.6, 3250.6, '45+8''', 'period_end', 'key', NULL, NULL, 'End of 1st half', '{"Argentina":2,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('3e8de8c9-8be8-4921-96ec-1a29ce8fd3d4', 'arg-fra-2022-final', 2, 0, 3296, '46''', 'period_start', 'key', NULL, NULL, '2nd half begins', '{"Argentina":2,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('13a4889d-ad08-41be-9125-24c4c7d7879a', 'arg-fra-2022-final', 2, 230, 3526, '49''', 'shot', 'detail', 'Argentina', 'Rodrigo De Paul', 'Rodrigo De Paul (Argentina) shot — saved, set up by Ángel Di María (xG 0.04)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.04,"outcome":"Saved","shot_type":"Open Play","body_part":"Right Foot","assist":"Ángel Di María","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('5683007d-fde4-40ee-aa5e-c1624424b24e', 'arg-fra-2022-final', 2, 552.5, 3848.5, '55''', 'card', 'key', 'France', 'Adrien Rabiot', 'Foul by Adrien Rabiot (France) on Rodrigo De Paul, midfield — YELLOW CARD for Adrien Rabiot', '{"Argentina":2,"France":0}'::jsonb, '{"card":"Yellow Card","foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('3366644c-6060-4544-95ed-7f17dedf70c6', 'arg-fra-2022-final', 2, 592.5, 3888.5, '55''', 'injury', 'detail', 'Argentina', 'Rodrigo De Paul', 'Play stopped for an injury to Rodrigo De Paul (Argentina)', '{"Argentina":2,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b4921423-4114-49ef-b266-386ba0671e2f', 'arg-fra-2022-final', 2, 663.2, 3959.2, '57''', 'foul', 'detail', 'Argentina', 'Nicolás Tagliafico', 'Foul by Nicolás Tagliafico (Argentina) on Randal Kolo Muani, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Randal Kolo Muani","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('56346f85-1533-4579-bb3c-6df7618b4dbf', 'arg-fra-2022-final', 2, 747.9, 4043.9, '58''', 'foul', 'detail', 'France', 'Kylian Mbappé', 'Foul by Kylian Mbappé (France) on Rodrigo De Paul, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('4ddb6b25-2919-47fa-bcdf-9059cd3e6ada', 'arg-fra-2022-final', 2, 752.9, 4048.9, '58''', 'injury', 'detail', 'Argentina', 'Rodrigo De Paul', 'Play stopped for an injury to Rodrigo De Paul (Argentina)', '{"Argentina":2,"France":0}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('43691970-1dad-4e11-bd29-48f640c55ea1', 'arg-fra-2022-final', 2, 801.4, 4097.4, '59''', 'shot', 'detail', 'Argentina', 'Julián Álvarez', 'Julián Álvarez (Argentina) shot — saved, set up by Ángel Di María (xG 0.06)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.06,"outcome":"Saved","shot_type":"Open Play","body_part":"Left Foot","assist":"Ángel Di María","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('be78b6e9-2f19-4620-9e4b-b518bd562537', 'arg-fra-2022-final', 2, 835.5, 4131.5, '59''', 'offside', 'detail', 'France', 'Kylian Mbappé', 'Offside: Theo Hernández (France) passes forward but Kylian Mbappé is caught offside', '{"Argentina":2,"France":0}'::jsonb, '{"passer":"Theo Hernández"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('9615ffbc-b513-45e6-9ccc-015234483f95', 'arg-fra-2022-final', 2, 891.8, 4187.8, '60''', 'shot', 'detail', 'Argentina', 'Lionel Messi', 'Lionel Messi (Argentina) shot — off target, set up by Ángel Di María (xG 0.12)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.12,"outcome":"Off T","shot_type":"Open Play","body_part":"Right Foot","assist":"Ángel Di María","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('3c5d3131-7851-4847-a751-98666932a559', 'arg-fra-2022-final', 2, 927.9, 4223.9, '61''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Raphaël Varane, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Raphaël Varane","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('7e84e10f-aa62-4c47-a090-13277abfebe3', 'arg-fra-2022-final', 2, 1055.1, 4351.1, '63''', 'foul', 'detail', 'Argentina', 'Nicolás Tagliafico', 'Foul by Nicolás Tagliafico (Argentina) on Antoine Griezmann, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Antoine Griezmann","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e7e1f696-1fe2-4b3a-b2ec-aeb36b0c8258', 'arg-fra-2022-final', 2, 1131.9, 4427.9, '64''', 'substitution', 'key', 'Argentina', 'Marcos Acuña', 'Substitution Argentina: Marcos Acuña ON, Ángel Di María OFF (tactical change)', '{"Argentina":2,"France":0}'::jsonb, '{"player_on":"Marcos Acuña","player_off":"Ángel Di María","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('88fc5a71-0b1d-4ccd-9cba-0216f28b1262', 'arg-fra-2022-final', 2, 1149.6, 4445.6, '65''', 'tactical_shift', 'detail', 'France', NULL, 'France change shape to 4-2-3-1', '{"Argentina":2,"France":0}'::jsonb, '{"formation":"4-2-3-1","lineup":["Hugo Lloris (Goalkeeper)","Jules Koundé (Right Back)","Raphaël Varane (Right Center Back)","Dayotchanculle Upamecano (Left Center Back)","Theo Hernández (Left Back)","Aurélien Tchouaméni (Right Defensive Midfield)","Adrien Rabiot (Left Defensive Midfield)","Randal Kolo Muani (Right Wing)","Antoine Griezmann (Center Attacking Midfield)","Kylian Mbappé (Left Wing)","Marcus Thuram (Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('9f6285ff-9b32-4a46-a4a0-74c1ca89276c', 'arg-fra-2022-final', 2, 1335.1, 4631.1, '68''', 'shot', 'detail', 'France', 'Randal Kolo Muani', 'Randal Kolo Muani (France) shot — off target, set up by Antoine Griezmann (xG 0.1)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.1,"outcome":"Off T","shot_type":"Open Play","body_part":"Head","assist":"Antoine Griezmann","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('50f1d8b0-d889-429d-a11a-6062ccd14478', 'arg-fra-2022-final', 2, 1420.8, 4716.8, '69''', 'handball', 'detail', 'Argentina', 'Enzo Fernandez', 'Handball by Enzo Fernandez (Argentina), midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":"Handball","penalty":false,"victim":null,"advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('b2d43671-a3e6-4709-9c0c-646442c1074c', 'arg-fra-2022-final', 2, 1509.2, 4805.2, '71''', 'shot', 'detail', 'France', 'Kylian Mbappé', 'Kylian Mbappé (France) shot — off target (xG 0.05)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.05,"outcome":"Off T","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('3c9df00b-0b30-4548-9cd1-ceff03cc9919', 'arg-fra-2022-final', 2, 1527.9, 4823.9, '71''', 'substitution', 'key', 'France', 'Eduardo Camavinga', 'Substitution France: Eduardo Camavinga ON, Theo Hernández OFF (tactical change)', '{"Argentina":2,"France":0}'::jsonb, '{"player_on":"Eduardo Camavinga","player_off":"Theo Hernández","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('43fe1865-0aa9-4bb1-bf33-a2871df4589b', 'arg-fra-2022-final', 2, 1529.7, 4825.7, '71''', 'substitution', 'key', 'France', 'Kingsley Coman', 'Substitution France: Kingsley Coman ON, Antoine Griezmann OFF (tactical change)', '{"Argentina":2,"France":0}'::jsonb, '{"player_on":"Kingsley Coman","player_off":"Antoine Griezmann","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('43b2d123-6945-4a7c-8292-f7792af341f9', 'arg-fra-2022-final', 2, 1591.2, 4887.2, '72''', 'shot', 'detail', 'Argentina', 'Enzo Fernandez', 'Enzo Fernandez (Argentina) shot — saved, set up by Lionel Messi (xG 0.04)', '{"Argentina":2,"France":0}'::jsonb, '{"xg":0.04,"outcome":"Saved","shot_type":"Open Play","body_part":"Right Foot","assist":"Lionel Messi","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('af7bfb2a-d02f-4512-8430-0fe330aac422', 'arg-fra-2022-final', 2, 1672.7, 4968.7, '73''', 'tactical_shift', 'detail', 'France', NULL, 'France change shape to 4-4-2', '{"Argentina":2,"France":0}'::jsonb, '{"formation":"4-4-2","lineup":["Hugo Lloris (Goalkeeper)","Jules Koundé (Right Back)","Raphaël Varane (Right Center Back)","Dayotchanculle Upamecano (Left Center Back)","Eduardo Camavinga (Left Back)","Aurélien Tchouaméni (Right Defensive Midfield)","Adrien Rabiot (Left Defensive Midfield)","Kingsley Coman (Right Midfield)","Randal Kolo Muani (Left Midfield)","Marcus Thuram (Right Center Forward)","Kylian Mbappé (Left Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('a70ef6af-a7e2-4f75-90e5-d2348827a91d', 'arg-fra-2022-final', 2, 1689.5, 4985.5, '74''', 'foul', 'detail', 'France', 'Aurélien Tchouaméni', 'Foul by Aurélien Tchouaméni (France) on Cristian Romero, attacking third', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Cristian Romero","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e454d741-3a2b-4587-89b1-1148803dcdd2', 'arg-fra-2022-final', 2, 1745.5, 5041.5, '75''', 'tactical_shift', 'detail', 'France', NULL, 'France change shape to 4-4-2', '{"Argentina":2,"France":0}'::jsonb, '{"formation":"4-4-2","lineup":["Hugo Lloris (Goalkeeper)","Jules Koundé (Right Back)","Raphaël Varane (Right Center Back)","Dayotchanculle Upamecano (Left Center Back)","Eduardo Camavinga (Left Back)","Aurélien Tchouaméni (Right Defensive Midfield)","Adrien Rabiot (Left Defensive Midfield)","Kingsley Coman (Right Midfield)","Marcus Thuram (Left Midfield)","Randal Kolo Muani (Right Center Forward)","Kylian Mbappé (Left Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('abb4ccaf-977e-4772-9b30-0e8418cd4534', 'arg-fra-2022-final', 2, 1788.1, 5084.1, '75''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Kingsley Coman, midfield (advantage played)', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Kingsley Coman","advantage":true,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('67e59bb1-c8c5-4657-b189-8d62b0007053', 'arg-fra-2022-final', 2, 1870.7, 5166.7, '77''', 'foul', 'detail', 'France', 'Eduardo Camavinga', 'Foul by Eduardo Camavinga (France) on Rodrigo De Paul, midfield', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('87769b1a-bdca-4e9b-b2fd-e8bb95313063', 'arg-fra-2022-final', 2, 1993.3, 5289.3, '79''', 'penalty_awarded', 'key', 'Argentina', 'Nicolás Otamendi', 'Foul by Nicolás Otamendi (Argentina) on Randal Kolo Muani, inside Argentina''s own penalty area — PENALTY to France', '{"Argentina":2,"France":0}'::jsonb, '{"card":null,"foul_type":null,"penalty":true,"victim":"Randal Kolo Muani","advantage":false,"zone":"inside Argentina''s own penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6cc0d5e2-6999-4006-8a7a-34de4cbe3ffd', 'arg-fra-2022-final', 2, 2065, 5361, '80''', 'goal', 'key', 'France', 'Kylian Mbappé', 'GOAL! Kylian Mbappé scores for France (penalty). Argentina 2–1 France', '{"Argentina":2,"France":1}'::jsonb, '{"xg":0.78,"shot_type":"Penalty","body_part":"Right Foot","assist":null}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('03fb2918-e1e7-4ec8-89ff-7bc5531e853d', 'arg-fra-2022-final', 2, 2159, 5455, '81''', 'goal', 'key', 'France', 'Kylian Mbappé', 'GOAL! Kylian Mbappé scores for France (right foot volley shot, assisted by Marcus Thuram). Argentina 2–2 France', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.1,"shot_type":"Open Play","body_part":"Right Foot","assist":"Marcus Thuram"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('fe277079-395a-4ff3-bb29-e99d93014014', 'arg-fra-2022-final', 2, 2303.7, 5599.7, '84''', 'shot', 'detail', 'Argentina', 'Enzo Fernandez', 'Enzo Fernandez (Argentina) shot — blocked, set up by Marcos Acuña (xG 0.03)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.03,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":"Marcos Acuña","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('c51e1110-13f7-4b73-8297-80abb4f65e11', 'arg-fra-2022-final', 2, 2385.3, 5681.3, '85''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Aurélien Tchouaméni, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Aurélien Tchouaméni","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d0463ffb-ee9c-47ef-8175-409eb2c435fa', 'arg-fra-2022-final', 2, 2446.5, 5742.5, '86''', 'foul', 'detail', 'Argentina', 'Nicolás Otamendi', 'Foul by Nicolás Otamendi (Argentina) on Randal Kolo Muani, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Randal Kolo Muani","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8f75db1a-1ee2-4ff8-b211-1c46d9a76a69', 'arg-fra-2022-final', 2, 2484.4, 5780.4, '87''', 'card', 'key', 'France', 'Marcus Thuram', 'Simulation (dive) by Marcus Thuram (France), inside the opponents'' penalty area — YELLOW CARD for Marcus Thuram', '{"Argentina":2,"France":2}'::jsonb, '{"card":"Yellow Card","foul_type":"Dive","penalty":false,"victim":null,"advantage":false,"zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('050c2199-7a48-4fa3-b769-453a2c8c99e7', 'arg-fra-2022-final', 2, 2539.3, 5835.3, '88''', 'foul', 'detail', 'Argentina', 'Julián Álvarez', 'Foul by Julián Álvarez (Argentina) on Adrien Rabiot, attacking third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Adrien Rabiot","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('599f811c-d3e2-49f6-b2df-830f4083a179', 'arg-fra-2022-final', 2, 2539.3, 5835.3, '88''', 'injury', 'detail', 'Argentina', 'Julián Álvarez', 'Play stopped for an injury to Julián Álvarez (Argentina)', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('14c26d07-135f-44b6-8e73-08966f9e5eb6', 'arg-fra-2022-final', 2, 2546.5, 5842.5, '88''', 'injury', 'detail', 'France', 'Adrien Rabiot', 'Play stopped for an injury to Adrien Rabiot (France)', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('22fea401-6836-45bb-bfbd-fadd4ed0b237', 'arg-fra-2022-final', 2, 2718.9, 6014.9, '90+1''', 'offside', 'detail', 'France', 'Marcus Thuram', 'Offside: Dayotchanculle Upamecano (France) passes forward but Marcus Thuram is caught offside', '{"Argentina":2,"France":2}'::jsonb, '{"passer":"Dayotchanculle Upamecano"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('e762b216-4f72-4123-8ad1-9155bbff07dc', 'arg-fra-2022-final', 2, 2794.8, 6090.8, '90+2''', 'foul', 'detail', 'Argentina', 'Cristian Romero', 'Foul by Cristian Romero (Argentina) on Marcus Thuram, defensive third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Marcus Thuram","advantage":false,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('5dbcde3d-ba75-483d-a65f-72d2b99ff713', 'arg-fra-2022-final', 2, 2877.9, 6173.9, '90+3''', 'shot', 'detail', 'France', 'Kylian Mbappé', 'Kylian Mbappé (France) shot — blocked (xG 0.03)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.03,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6042d91e-1d3f-48e2-a9f4-3d28d7a25da1', 'arg-fra-2022-final', 2, 2922.9, 6218.9, '90+4''', 'foul', 'detail', 'Argentina', 'Enzo Fernandez', 'Foul by Enzo Fernandez (Argentina) on Kingsley Coman, defensive third (advantage played)', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Kingsley Coman","advantage":true,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8d2a6599-cc25-41a2-acde-41d10194b5bd', 'arg-fra-2022-final', 2, 2925.5, 6221.5, '90+4''', 'shot', 'detail', 'France', 'Adrien Rabiot', 'Adrien Rabiot (France) shot — saved, set up by Eduardo Camavinga (xG 0.09)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.09,"outcome":"Saved","shot_type":"Open Play","body_part":"Left Foot","assist":"Eduardo Camavinga","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('ed616313-3980-444e-805f-9951a40d8a52', 'arg-fra-2022-final', 2, 2975.2, 6271.2, '90+5''', 'card', 'key', 'France', 'Olivier Giroud', 'YELLOW CARD for Olivier Giroud (France) — off-the-ball / unsporting behaviour, not for a foul', '{"Argentina":2,"France":2}'::jsonb, '{"card":"Yellow Card","reason":"Bad behaviour"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('21808895-7b00-4b7b-ae22-64d9c1181e59', 'arg-fra-2022-final', 2, 3048.6, 6344.6, '90+6''', 'foul', 'detail', 'Argentina', 'Nicolás Tagliafico', 'Foul by Nicolás Tagliafico (Argentina) on Adrien Rabiot, attacking third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Adrien Rabiot","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('867b8791-49c0-4d98-a976-c0b4cfc1cb5a', 'arg-fra-2022-final', 2, 3097.2, 6393.2, '90+7''', 'shot', 'detail', 'Argentina', 'Lionel Messi', 'Lionel Messi (Argentina) shot — saved, set up by Rodrigo De Paul (xG 0.04)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.04,"outcome":"Saved","shot_type":"Open Play","body_part":"Left Foot","assist":"Rodrigo De Paul","zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('4b295434-7285-4337-95b4-26395b799643', 'arg-fra-2022-final', 2, 3153.6, 6449.6, '90+8''', 'card', 'key', 'Argentina', 'Marcos Acuña', 'Foul by Marcos Acuña (Argentina) on Kingsley Coman, attacking third — YELLOW CARD for Marcos Acuña', '{"Argentina":2,"France":2}'::jsonb, '{"card":"Yellow Card","foul_type":null,"penalty":false,"victim":"Kingsley Coman","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('440c7e28-8628-4082-8f69-b465068a927b', 'arg-fra-2022-final', 2, 3217.9, 6513.9, '90+9''', 'period_end', 'key', NULL, NULL, 'End of 2nd half', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('97489f9c-4763-4be3-a1c5-453b71c710a8', 'arg-fra-2022-final', 3, 0, 6604, '91''', 'period_start', 'key', NULL, NULL, 'Extra time 1st half begins', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('c7266755-5003-418c-bf4f-f7da41d47840', 'arg-fra-2022-final', 3, 0, 6604, '91''', 'substitution', 'key', 'Argentina', 'Gonzalo Montiel', 'Substitution Argentina: Gonzalo Montiel ON, Nahuel Molina OFF (tactical change)', '{"Argentina":2,"France":2}'::jsonb, '{"player_on":"Gonzalo Montiel","player_off":"Nahuel Molina","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('efb58d41-46a0-4a47-98d0-6af184197f37', 'arg-fra-2022-final', 3, 36, 6640, '91''', 'foul', 'detail', 'France', 'Adrien Rabiot', 'Foul by Adrien Rabiot (France) on Rodrigo De Paul, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Rodrigo De Paul","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('f0a2ebda-0b49-4b82-9e77-a1560e1fcde8', 'arg-fra-2022-final', 3, 77, 6681, '92''', 'foul', 'detail', 'France', 'Marcus Thuram', 'Foul by Marcus Thuram (France) on Gonzalo Montiel, defensive third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Gonzalo Montiel","advantage":false,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d8c05bb0-ddb1-4ff2-9dbf-ba17b00a5359', 'arg-fra-2022-final', 3, 125.4, 6729.4, '93''', 'shot', 'detail', 'Argentina', 'Alexis Mac Allister', 'Alexis Mac Allister (Argentina) shot — off target (xG 0.02)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.02,"outcome":"Off T","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('ae7aba18-0984-47c5-a275-248e539a0e0e', 'arg-fra-2022-final', 3, 172.5, 6776.5, '93''', 'foul', 'detail', 'Argentina', 'Lionel Messi', 'Foul by Lionel Messi (Argentina) on Eduardo Camavinga, attacking third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Eduardo Camavinga","advantage":false,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('79dbfa4b-2f10-4f17-8b10-816eaff6ef65', 'arg-fra-2022-final', 3, 274.7, 6878.7, '95''', 'foul', 'detail', 'Argentina', 'Marcos Acuña', 'Foul by Marcos Acuña (Argentina) on Jules Koundé, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Jules Koundé","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('5688fcf1-1b7a-4938-8d14-92b87c198d95', 'arg-fra-2022-final', 3, 310.4, 6914.4, '96''', 'substitution', 'key', 'France', 'Youssouf Fofana', 'Substitution France: Youssouf Fofana ON, Adrien Rabiot OFF (tactical change)', '{"Argentina":2,"France":2}'::jsonb, '{"player_on":"Youssouf Fofana","player_off":"Adrien Rabiot","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('5d536c27-ecb7-4e13-985c-d87f3e2eb925', 'arg-fra-2022-final', 3, 327.3, 6931.3, '96''', 'foul', 'detail', 'Argentina', 'Enzo Fernandez', 'Foul by Enzo Fernandez (Argentina) on Eduardo Camavinga, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Eduardo Camavinga","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d341d94a-a4d0-442a-98df-98d1b852280a', 'arg-fra-2022-final', 3, 358, 6962, '96''', 'offside', 'detail', 'France', 'Kylian Mbappé', 'Offside: Dayotchanculle Upamecano (France) passes forward but Kylian Mbappé is caught offside', '{"Argentina":2,"France":2}'::jsonb, '{"passer":"Dayotchanculle Upamecano"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('17f3767b-c88c-46aa-94dc-5ad2b4a9bcf6', 'arg-fra-2022-final', 3, 384.1, 6988.1, '97''', 'injury', 'detail', 'Argentina', 'Julián Álvarez', 'Play stopped for an injury to Julián Álvarez (Argentina)', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('cc676ca2-190d-401c-95ee-8acf6a58d694', 'arg-fra-2022-final', 3, 551.1, 7155.1, '100''', 'foul', 'detail', 'Argentina', 'Gonzalo Montiel', 'Foul by Gonzalo Montiel (Argentina) on Youssouf Fofana, defensive third', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Youssouf Fofana","advantage":false,"zone":"defensive third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('db8267ad-256a-450d-997f-382a4d545634', 'arg-fra-2022-final', 3, 594.5, 7198.5, '100''', 'shot', 'detail', 'France', 'Youssouf Fofana', 'Youssouf Fofana (France) shot — blocked (xG 0.02)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.02,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('bae39b9d-d6b8-4c4b-8840-39b3ac3260e2', 'arg-fra-2022-final', 3, 626.4, 7230.4, '101''', 'offside', 'detail', 'France', 'Raphaël Varane', 'Offside: Jules Koundé (France) passes forward but Raphaël Varane is caught offside', '{"Argentina":2,"France":2}'::jsonb, '{"passer":"Jules Koundé"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('1ffcf328-9f45-46b6-90ab-0404571f2fe6', 'arg-fra-2022-final', 3, 679.2, 7283.2, '102''', 'foul', 'detail', 'France', 'Randal Kolo Muani', 'Foul by Randal Kolo Muani (France) on Alexis Mac Allister, midfield', '{"Argentina":2,"France":2}'::jsonb, '{"card":null,"foul_type":null,"penalty":false,"victim":"Alexis Mac Allister","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8939a18c-593c-41fc-b86d-308cd189fca1', 'arg-fra-2022-final', 3, 697.5, 7301.5, '102''', 'substitution', 'key', 'Argentina', 'Leandro Paredes', 'Substitution Argentina: Leandro Paredes ON, Rodrigo De Paul OFF (tactical change)', '{"Argentina":2,"France":2}'::jsonb, '{"player_on":"Leandro Paredes","player_off":"Rodrigo De Paul","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('1e6477ea-098a-41d5-96d1-d2944e38f46c', 'arg-fra-2022-final', 3, 709.3, 7313.3, '102''', 'substitution', 'key', 'Argentina', 'Lautaro Martínez', 'Substitution Argentina: Lautaro Martínez ON, Julián Álvarez OFF (tactical change)', '{"Argentina":2,"France":2}'::jsonb, '{"player_on":"Lautaro Martínez","player_off":"Julián Álvarez","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('39376cef-49a0-484a-ab0d-64a9c023024e', 'arg-fra-2022-final', 3, 736.3, 7340.3, '103''', 'tactical_shift', 'detail', 'Argentina', NULL, 'Argentina change shape to 4-3-3', '{"Argentina":2,"France":2}'::jsonb, '{"formation":"4-3-3","lineup":["Emiliano Martínez (Goalkeeper)","Gonzalo Montiel (Right Back)","Cristian Romero (Right Center Back)","Nicolás Otamendi (Left Center Back)","Nicolás Tagliafico (Left Back)","Leandro Paredes (Center Defensive Midfield)","Enzo Fernandez (Right Center Midfield)","Alexis Mac Allister (Left Center Midfield)","Lionel Messi (Right Wing)","Marcos Acuña (Left Wing)","Lautaro Martínez (Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d3ba40fa-09d6-4488-b17d-672aaa2928d7', 'arg-fra-2022-final', 3, 868, 7472, '105''', 'shot', 'detail', 'Argentina', 'Lautaro Martínez', 'Lautaro Martínez (Argentina) shot — blocked, set up by Lionel Messi (xG 0.23)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.23,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":"Lionel Messi","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('a1654330-3747-4a25-b244-26ba2884c91c', 'arg-fra-2022-final', 3, 870.4, 7474.4, '105''', 'shot', 'detail', 'Argentina', 'Gonzalo Montiel', 'Gonzalo Montiel (Argentina) shot — blocked (xG 0.02)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.02,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('5d7d4f2f-62da-4de9-90e3-3660ba17c4f3', 'arg-fra-2022-final', 3, 941.2, 7545.2, '105+1''', 'shot', 'detail', 'Argentina', 'Lautaro Martínez', 'Lautaro Martínez (Argentina) shot — off target, set up by Marcos Acuña (xG 0.14)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.14,"outcome":"Off T","shot_type":"Open Play","body_part":"Left Foot","assist":"Marcos Acuña","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('2cc2184c-c5ef-43ba-8347-3d0889ae4703', 'arg-fra-2022-final', 3, 964.6, 7568.6, '105+2''', 'period_end', 'key', NULL, NULL, 'End of extra time 1st half', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('55134cc4-8d38-44e2-9303-ce53ab7feb3d', 'arg-fra-2022-final', 4, 0, 7613, '106''', 'period_start', 'key', NULL, NULL, 'Extra time 2nd half begins', '{"Argentina":2,"France":2}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('8bb8c7b5-9c14-4dfa-9279-0548ee8076db', 'arg-fra-2022-final', 4, 115.7, 7728.7, '107''', 'shot', 'detail', 'Argentina', 'Lionel Messi', 'Lionel Messi (Argentina) shot — saved, set up by Gonzalo Montiel (xG 0.02)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.02,"outcome":"Saved","shot_type":"Open Play","body_part":"Left Foot","assist":"Gonzalo Montiel","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('40cbfd91-87d9-4df8-a575-533b5c26767f', 'arg-fra-2022-final', 4, 177, 7790, '108''', 'shot', 'detail', 'Argentina', 'Lautaro Martínez', 'Lautaro Martínez (Argentina) shot — saved, set up by Enzo Fernandez (xG 0.1)', '{"Argentina":2,"France":2}'::jsonb, '{"xg":0.1,"outcome":"Saved","shot_type":"Open Play","body_part":"Right Foot","assist":"Enzo Fernandez","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('54b889ec-6026-49ea-a913-e883dbe6e301', 'arg-fra-2022-final', 4, 178.1, 7791.1, '108''', 'goal', 'key', 'Argentina', 'Lionel Messi', 'GOAL! Lionel Messi scores for Argentina (right foot half volley shot). Argentina 3–2 France', '{"Argentina":3,"France":2}'::jsonb, '{"xg":0.49,"shot_type":"Open Play","body_part":"Right Foot","assist":null}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('c001d49f-247b-40d8-b247-38c7adcdebe4', 'arg-fra-2022-final', 4, 448.1, 8061.1, '113''', 'substitution', 'key', 'France', 'Ibrahima Konaté', 'Substitution France: Ibrahima Konaté ON, Raphaël Varane OFF (injury change)', '{"Argentina":3,"France":2}'::jsonb, '{"player_on":"Ibrahima Konaté","player_off":"Raphaël Varane","reason":"Injury"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('19e301d2-38dd-4cbd-8bc2-61d2b46b9951', 'arg-fra-2022-final', 4, 507.1, 8120.1, '114''', 'card', 'key', 'Argentina', 'Leandro Paredes', 'Foul by Leandro Paredes (Argentina) on Eduardo Camavinga, midfield — YELLOW CARD for Leandro Paredes', '{"Argentina":3,"France":2}'::jsonb, '{"card":"Yellow Card","foul_type":null,"penalty":false,"victim":"Eduardo Camavinga","advantage":false,"zone":"midfield"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('6e81c350-5788-4f84-891a-92db9bfbf0db', 'arg-fra-2022-final', 4, 622.2, 8235.2, '116''', 'substitution', 'key', 'Argentina', 'Germán Pezzella', 'Substitution Argentina: Germán Pezzella ON, Alexis Mac Allister OFF (tactical change)', '{"Argentina":3,"France":2}'::jsonb, '{"player_on":"Germán Pezzella","player_off":"Alexis Mac Allister","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('de8d4b3f-17eb-47ba-84f0-b8aac05d91c3', 'arg-fra-2022-final', 4, 632.2, 8245.2, '116''', 'tactical_shift', 'detail', 'Argentina', NULL, 'Argentina change shape to 3-5-2', '{"Argentina":3,"France":2}'::jsonb, '{"formation":"3-5-2","lineup":["Emiliano Martínez (Goalkeeper)","Cristian Romero (Right Center Back)","Germán Pezzella (Center Back)","Nicolás Otamendi (Left Center Back)","Gonzalo Montiel (Right Wing Back)","Nicolás Tagliafico (Left Wing Back)","Leandro Paredes (Center Defensive Midfield)","Enzo Fernandez (Right Center Midfield)","Marcos Acuña (Left Center Midfield)","Lionel Messi (Right Center Forward)","Lautaro Martínez (Left Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('08f2f203-cdc9-4146-99b6-818c5c32bf70', 'arg-fra-2022-final', 4, 638.9, 8251.9, '116''', 'shot', 'detail', 'France', 'Kylian Mbappé', 'Kylian Mbappé (France) shot — blocked (xG 0.03)', '{"Argentina":3,"France":2}'::jsonb, '{"xg":0.03,"outcome":"Blocked","shot_type":"Open Play","body_part":"Right Foot","assist":null,"zone":"attacking third"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('dcbf6fe6-7b7f-4066-978e-de1a3d6d70ff', 'arg-fra-2022-final', 4, 639.1, 8252.1, '116''', 'card', 'key', 'Argentina', 'Gonzalo Montiel', 'Handball by Gonzalo Montiel (Argentina), inside Argentina''s own penalty area — PENALTY to France — YELLOW CARD for Gonzalo Montiel', '{"Argentina":3,"France":2}'::jsonb, '{"card":"Yellow Card","foul_type":"Handball","penalty":true,"victim":null,"advantage":false,"zone":"inside Argentina''s own penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d9b92dbd-4fea-4f48-b2fb-d7222eab2dbd', 'arg-fra-2022-final', 4, 725.2, 8338.2, '118''', 'goal', 'key', 'France', 'Kylian Mbappé', 'GOAL! Kylian Mbappé scores for France (penalty). Argentina 3–3 France', '{"Argentina":3,"France":3}'::jsonb, '{"xg":0.78,"shot_type":"Penalty","body_part":"Right Foot","assist":null}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('838765c8-45c7-4379-857c-f103770acbfc', 'arg-fra-2022-final', 4, 935.8, 8548.8, '120+1''', 'substitution', 'key', 'France', 'Axel Disasi', 'Substitution France: Axel Disasi ON, Jules Koundé OFF (tactical change)', '{"Argentina":3,"France":3}'::jsonb, '{"player_on":"Axel Disasi","player_off":"Jules Koundé","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('27c68f97-cc44-4fb8-9703-0a4de1c9f6ed', 'arg-fra-2022-final', 4, 946.2, 8559.2, '120+1''', 'substitution', 'key', 'Argentina', 'Paulo Dybala', 'Substitution Argentina: Paulo Dybala ON, Nicolás Tagliafico OFF (tactical change)', '{"Argentina":3,"France":3}'::jsonb, '{"player_on":"Paulo Dybala","player_off":"Nicolás Tagliafico","reason":"Tactical"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('68fe5a2d-6340-42e3-9c72-1c6d55815da7', 'arg-fra-2022-final', 4, 948.3, 8561.3, '120+1''', 'tactical_shift', 'detail', 'Argentina', NULL, 'Argentina change shape to 3-5-2', '{"Argentina":3,"France":3}'::jsonb, '{"formation":"3-5-2","lineup":["Emiliano Martínez (Goalkeeper)","Cristian Romero (Right Center Back)","Germán Pezzella (Center Back)","Nicolás Otamendi (Left Center Back)","Gonzalo Montiel (Right Wing Back)","Marcos Acuña (Left Wing Back)","Leandro Paredes (Center Defensive Midfield)","Enzo Fernandez (Right Center Midfield)","Paulo Dybala (Left Center Midfield)","Lionel Messi (Right Center Forward)","Lautaro Martínez (Left Center Forward)"]}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('7963f4cf-e710-42d4-b9ee-2d9b1b7ea12b', 'arg-fra-2022-final', 4, 1019.8, 8632.8, '120+2''', 'offside', 'detail', 'Argentina', 'Lautaro Martínez', 'Offside: Lionel Messi (Argentina) passes forward but Lautaro Martínez is caught offside', '{"Argentina":3,"France":3}'::jsonb, '{"passer":"Lionel Messi"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('959edead-09fb-40b0-b6a3-72e73bd30d5a', 'arg-fra-2022-final', 4, 1064.4, 8677.4, '120+3''', 'shot', 'key', 'France', 'Randal Kolo Muani', 'Big chance: Randal Kolo Muani (France) shot — saved, set up by Ibrahima Konaté (xG 0.28)', '{"Argentina":3,"France":3}'::jsonb, '{"xg":0.28,"outcome":"Saved","shot_type":"Open Play","body_part":"Right Foot","assist":"Ibrahima Konaté","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('449f2702-ad18-4bc8-a9ef-59fb1dc1a707', 'arg-fra-2022-final', 4, 1079.8, 8692.8, '120+3''', 'shot', 'detail', 'Argentina', 'Lautaro Martínez', 'Lautaro Martínez (Argentina) shot — off target, set up by Gonzalo Montiel (xG 0.11)', '{"Argentina":3,"France":3}'::jsonb, '{"xg":0.11,"outcome":"Off T","shot_type":"Open Play","body_part":"Head","assist":"Gonzalo Montiel","zone":"inside the opponents'' penalty area"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('da654dbc-5e9d-4067-ab4a-2db561a77c8f', 'arg-fra-2022-final', 4, 1147.5, 8760.5, '120+5''', 'period_end', 'key', NULL, NULL, 'End of extra time 2nd half', '{"Argentina":3,"France":3}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('f792bb69-f5b3-4945-82f8-3b98382e6605', 'arg-fra-2022-final', 5, 0, 8838, 'Pens', 'period_start', 'key', NULL, NULL, 'Penalty shootout begins', '{"Argentina":3,"France":3}'::jsonb, '{}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('d0f76056-0d67-4aae-b44a-83bef0b1cf27', 'arg-fra-2022-final', 5, 13.4, 8851.4, 'Pens', 'shootout_kick', 'key', 'France', 'Kylian Mbappé', 'Kylian Mbappé (France) SCORES in the shootout. Shootout: Argentina 0–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":0,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('2a15edb5-2a54-41d5-afe9-87e447389b18', 'arg-fra-2022-final', 5, 62.2, 8900.2, 'Pens', 'shootout_kick', 'key', 'Argentina', 'Lionel Messi', 'Lionel Messi (Argentina) SCORES in the shootout. Shootout: Argentina 1–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":1,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('97439112-dfb5-4bd5-9967-554095296096', 'arg-fra-2022-final', 5, 102, 8940, 'Pens', 'shootout_kick', 'key', 'France', 'Kingsley Coman', 'Kingsley Coman (France) MISSES (saved) in the shootout. Shootout: Argentina 1–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Saved","shootout_after":{"Argentina":1,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('50dcde1a-faa3-4eec-a0cd-3f09a7cf763a', 'arg-fra-2022-final', 5, 147.2, 8985.2, 'Pens', 'shootout_kick', 'key', 'Argentina', 'Paulo Dybala', 'Paulo Dybala (Argentina) SCORES in the shootout. Shootout: Argentina 2–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":2,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('54e27ba9-b9ae-44a3-ac8d-fc91e76a1b91', 'arg-fra-2022-final', 5, 209.3, 9047.3, 'Pens', 'shootout_kick', 'key', 'France', 'Aurélien Tchouaméni', 'Aurélien Tchouaméni (France) MISSES (off target) in the shootout. Shootout: Argentina 2–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Off T","shootout_after":{"Argentina":2,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('bcc6d4ae-f71c-4566-bf2d-c12f910eb526', 'arg-fra-2022-final', 5, 256.7, 9094.7, 'Pens', 'shootout_kick', 'key', 'Argentina', 'Leandro Paredes', 'Leandro Paredes (Argentina) SCORES in the shootout. Shootout: Argentina 3–1 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":3,"France":1}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('ad6e8237-8cb9-44f4-b9fb-356f066f3b2b', 'arg-fra-2022-final', 5, 297.5, 9135.5, 'Pens', 'card', 'key', 'Argentina', 'Emiliano Martínez', 'YELLOW CARD for Emiliano Martínez (Argentina) — off-the-ball / unsporting behaviour, not for a foul', '{"Argentina":3,"France":3}'::jsonb, '{"card":"Yellow Card","reason":"Bad behaviour"}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('59ebe83e-616a-4288-89fd-a0246b53d48f', 'arg-fra-2022-final', 5, 309.8, 9147.8, 'Pens', 'shootout_kick', 'key', 'France', 'Randal Kolo Muani', 'Randal Kolo Muani (France) SCORES in the shootout. Shootout: Argentina 3–2 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":3,"France":2}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('66eaf262-999f-4953-a924-f1b596de4dbf', 'arg-fra-2022-final', 5, 357.9, 9195.9, 'Pens', 'shootout_kick', 'key', 'Argentina', 'Gonzalo Montiel', 'Gonzalo Montiel (Argentina) SCORES in the shootout. Shootout: Argentina 4–2 France', '{"Argentina":3,"France":3}'::jsonb, '{"outcome":"Goal","shootout_after":{"Argentina":4,"France":2}}'::jsonb, false, NULL);
INSERT INTO public.match_events (id, match_id, period, elapsed_in_period_s, video_time, clock, type, importance, team, player, description, score_after, data, approximate, seq)
VALUES ('4f66bdf1-2c51-483a-b45a-89b525bc23c0', 'arg-fra-2022-final', 5, 358.9, 9196.9, 'Pens', 'period_end', 'key', NULL, NULL, 'End of penalty shootout', '{"Argentina":3,"France":3}'::jsonb, '{}'::jsonb, false, NULL);
