"use client";

import { useEffect, useState } from "react";
import type { EntityProfile, EntityRelatedResponse } from "@/lib/types/entity";

type ProfileState = {
  entity: EntityProfile | null;
  related: EntityRelatedResponse | null;
  loading: boolean;
  error: string | null;
};

export function useEntityProfile(entityId: string | null): ProfileState {
  const [state, setState] = useState<ProfileState>({
    entity: null,
    related: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!entityId) {
      setState({ entity: null, related: null, loading: false, error: "No entity ID" });
      return;
    }

    let cancelled = false;

    async function load() {
      setState((prev) => ({ ...prev, loading: true, error: null }));
      try {

        const authHeader: Record<string, string> = {};
        const [profileRes, relatedRes] = await Promise.all([
          fetch(`/api/entities/${encodeURIComponent(entityId!)}`, { cache: "no-store", headers: authHeader }),
          fetch(`/api/entities/${encodeURIComponent(entityId!)}/related`, { cache: "no-store", headers: authHeader }),
        ]);

        if (!profileRes.ok) {
          const body = await profileRes.json().catch(() => ({})) as { detail?: unknown };
          const msg =
            typeof body?.detail === "string"
              ? body.detail
              : profileRes.status === 404
              ? "Entity not found"
              : `Error ${profileRes.status}`;
          if (!cancelled) setState({ entity: null, related: null, loading: false, error: msg });
          return;
        }

        const entity = (await profileRes.json()) as EntityProfile;
        const related = relatedRes.ok
          ? ((await relatedRes.json()) as EntityRelatedResponse)
          : null;

        if (!cancelled) setState({ entity, related, loading: false, error: null });
      } catch (err) {
        if (!cancelled) {
          setState({
            entity: null,
            related: null,
            loading: false,
            error: err instanceof Error ? err.message : "Request failed",
          });
        }
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [entityId]);

  return state;
}
