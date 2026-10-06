CREATE TABLE public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL
);

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
