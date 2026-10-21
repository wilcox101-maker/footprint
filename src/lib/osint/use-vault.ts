import { useEffect, useState } from "react";

import { emptyVault, loadVault, VAULT_EVENT } from "@/lib/osint/store";
import type { Vault } from "@/lib/osint/types";

export function useVault() {
  const [vault, setVault] = useState<Vault>(emptyVault);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const sync = () => setVault(loadVault());
    sync();
    setReady(true);
    window.addEventListener(VAULT_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(VAULT_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  return { vault, ready };
}
