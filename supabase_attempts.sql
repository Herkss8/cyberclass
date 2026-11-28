-- CyberClass: additive migration. Run once in Supabase SQL Editor.
begin;
alter table public.cc_attempts add column if not exists answers jsonb;
alter table public.cc_attempts add column if not exists mode text not null default 'topic';
alter table public.cc_attempts add column if not exists client_attempt_id uuid;
create unique index if not exists cc_attempts_client_attempt_id_uidx on public.cc_attempts(client_attempt_id);
create index if not exists cc_attempts_created_at_idx on public.cc_attempts(created_at desc);

-- Preserve existing policies, but prohibit reading other users' detailed attempts.
alter table public.cc_attempts enable row level security;
drop policy if exists cc_attempts_private_read_v2 on public.cc_attempts;
create policy cc_attempts_private_read_v2 on public.cc_attempts as restrictive for select to public
using (auth.uid() is not null and (user_id = auth.uid() or coalesce(public.is_admin(), false)));

create or replace function public.cc_save_attempt_v2(
  p_owner uuid, p_id uuid, p_group text, p_topic text, p_correct integer,
  p_total integer, p_completed boolean, p_mode text, p_answers jsonb, p_created_at timestamptz
) returns void language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null or auth.uid() <> p_owner or p_owner is null then
    raise exception 'Not authorized' using errcode = '42501';
  end if;
  if p_id is null or p_group is null or p_topic is null or p_completed is null
    or p_mode is null or p_mode not in ('topic','adaptive')
    or p_total is null or p_total < 1 or p_total > 10000
    or p_correct is null or p_correct < 0 or p_correct > p_total
    or p_answers is null or jsonb_typeof(p_answers) <> 'array'
    or octet_length(p_answers::text) > 4000000 then
    raise exception 'Invalid attempt' using errcode = '22023';
  end if;
  if jsonb_array_length(p_answers) <> p_total or
    (select count(*) from jsonb_array_elements(p_answers) a where a->'correct' = 'true'::jsonb) <> p_correct then
    raise exception 'Invalid answer count' using errcode = '22023';
  end if;
  insert into public.cc_attempts(user_id, group_key, topic_key, correct, total, completed, mode, answers, client_attempt_id, created_at)
  values(auth.uid(), p_group, p_topic, p_correct, p_total, p_completed, p_mode, p_answers, p_id,
    least(coalesce(p_created_at, now()), now()))
  on conflict (client_attempt_id) do nothing;
end;
$$;
revoke all on function public.cc_save_attempt_v2(uuid,uuid,text,text,integer,integer,boolean,text,jsonb,timestamptz) from public, anon;
grant execute on function public.cc_save_attempt_v2(uuid,uuid,text,text,integer,integer,boolean,text,jsonb,timestamptz) to authenticated;

create or replace function public.cc_admin_attempts_v2(p_offset integer default 0, p_limit integer default 200, p_since timestamptz default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare result jsonb;
begin
  if auth.uid() is null or not coalesce(public.is_admin(), false) then
    raise exception 'Administrator only' using errcode = '42501';
  end if;
  select coalesce(jsonb_agg(to_jsonb(r) order by r.created_at desc, r.row_key), '[]'::jsonb) into result
  from (
    select a.user_id, u.email, p.display_name, a.group_key, a.topic_key, a.correct, a.total,
      a.completed, a.created_at, a.mode, a.answers, a.ctid::text as row_key
    from public.cc_attempts a
    left join auth.users u on u.id = a.user_id
    left join public.profiles p on p.id = a.user_id
    where p_since is null or a.created_at >= p_since
    order by a.created_at desc, a.ctid::text
    offset greatest(coalesce(p_offset,0),0) limit least(greatest(coalesce(p_limit,200),1),500)
  ) r;
  return result;
end;
$$;
revoke all on function public.cc_admin_attempts_v2(integer,integer,timestamptz) from public, anon;
grant execute on function public.cc_admin_attempts_v2(integer,integer,timestamptz) to authenticated;
commit;
notify pgrst, 'reload schema';
