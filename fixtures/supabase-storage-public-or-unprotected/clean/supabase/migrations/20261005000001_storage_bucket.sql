INSERT INTO storage.buckets (id, name, public) VALUES ('user_documents', 'user_documents', false);

CREATE POLICY "User storage access" ON storage.objects FOR SELECT USING (auth.uid() = owner);
