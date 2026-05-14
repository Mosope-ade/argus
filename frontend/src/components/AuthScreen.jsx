import { useState } from "react";

export default function AuthScreen({
  login,
  loading,
  error,
}) {
  const [password, setPassword] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(password);
  };

  return (
    <div className="h-screen bg-[#080c12] flex items-center justify-center">
      <div className="w-full max-w-md border border-[#1a2535] bg-[#0d1117] p-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl text-[#e2e8f0] font-bold tracking-widest">
            ARGUS
          </h1>

          <p className="text-[#4a6080] font-mono text-sm mt-2">
            Security Operations Console
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <input
            type="password"
            placeholder="Access Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-[#080c12] border border-[#1a2535] p-3 text-[#e2e8f0] font-mono outline-none focus:border-[#00d4ff]"
          />

          {error && (
            <div className="text-[#ff3c5a] text-sm font-mono mt-3">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-4 border border-[#00d4ff] text-[#00d4ff] p-3 font-mono hover:bg-[#00d4ff] hover:text-[#080c12] transition-colors"
          >
            {loading ? "Authenticating..." : "Authenticate"}
          </button>
        </form>
      </div>
    </div>
  );
}