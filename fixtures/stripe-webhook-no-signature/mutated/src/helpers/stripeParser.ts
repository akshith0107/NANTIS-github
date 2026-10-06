export async function parseIncomingEvent(req: Request) {
  // Indirectly parsing JSON without verifying signature header or calling constructEvent
  return await req.json();
}
