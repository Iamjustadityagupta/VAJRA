export function getApiBase() {
  const configured = import.meta.env.VITE_API_URL;
  if (configured) return configured.replace(/\/$/, '');
  if (typeof window !== 'undefined') return window.location.origin;
  return 'http://localhost:8000';
}
