// Runtime configuration injected by /env.js (written by the frontend image's entrypoint)
interface Window {
  ENV: {
    HASURA_ADMIN_SECRET: string;
  };
}
