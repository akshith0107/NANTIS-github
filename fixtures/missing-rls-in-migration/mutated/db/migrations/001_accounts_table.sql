-- Reformatted SQL migration creating accounts table without enabling RLS
create table if not exists public.accounts (
  acc_id uuid primary key default gen_random_uuid(),
  balance numeric not null default 0
);
