/** Canonical UI buckets (sidebar + legend) aligned with extractor/graph types. */
export type EntityCategoryKey =
  | "THREAT_ACTOR"
  | "WALLET"
  | "MALWARE"
  | "FORUM"
  | "C2_SERVER"
  | "CVE"
  | "PASTE_URL"
  | "ONION_URL"
  | "EMAIL"
  | "PGP_KEY"
  | "OTHER";

export type InvestigationStatus =
  | "pending"
  | "processing"
  | "completed"
  | "failed"
  | "cancelled"
  | "completed_no_results"
  | string;

export type InfraCluster = {
  type: "shared_ip" | "shared_nameserver" | string;
  ip?: string;
  nameserver?: string;
  domains: string[];
  description: string;
};

export type SourceEntry = {
  status: string;
  count?: number;
  requests?: number;
  [key: string]: unknown;
};

// Older saved investigations contain status strings; new runs include counts.
export type SourceResult = SourceEntry | string;

export type InvestigationSummary = {
  id: number;
  run_id: string;
  query: string;
  refined_query: string | null;
  status: string;
  created_at: string;
  completed_at: string | null;
  entity_count: number;
  page_count: number;
  graph_status: string | null;
  model_used: string | null;
  current_step: number | null;
  preset?: string | null;
  summary?: string | null;
  infrastructure_clusters?: InfraCluster[];
  paste_sources_used?: string[];
  sources_used?: Record<string, SourceResult>;
};

export type InvestigationEntity = {
  id: string;
  entity_type: string;
  value: string;
  confidence: number;
  priority_score?: number;
  priority_score_components?: {
    confidence: number;
    corroboration: number;
    freshness: number;
    centrality: number;
  };
  priority_score_centrality_contribution?: number;
  typed_relationship_degree?: number;
  category?: string;
  investigation_id?: string | null;
  context?: string | null;
  created_at?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  graph_node_id: string;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  freshness_tag?: string;
  freshness_label?: string;
  freshness_color?: string;
  source_count?: number;
  investigation_count?: number;
  corroborating_sources?: string[];
  cross_referenced?: boolean;
  defanged?: boolean;
};

export type GraphNodeJSON = {
  id: string;
  type: string;
  confidence?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  source_urls?: string[];
  metadata?: Record<string, unknown>;
};

export type GraphEdgeJSON = {
  source: string;
  target: string;
  type: string;
  confidence?: number;
  source_url?: string;
  timestamp?: string | null;
  metadata?: Record<string, unknown>;
};

export type InvestigationGraphResponse = {
  nodes: GraphNodeJSON[];
  edges: GraphEdgeJSON[];
  /**
   * Server-computed community partition: node_id → community_id (int).
   * Communities are computed once on the backend via greedy modularity
   * (networkx.greedy_modularity_communities) and returned in every render,
   * so the visualisation is deterministic and never blocks the browser.
   */
  communities?: Record<string, number>;
  community_count?: number;
};

export type GraphApiResponse = InvestigationGraphResponse & {
  graph_status?: string;
  total_entities?: number;
  filtered_entities?: number;
  min_confidence?: number;
  message?: string;
};

/** Map raw DB / extractor `entity_type` to sidebar category. */
export function entityTypeToCategory(entityType: string): EntityCategoryKey {
  const m: Record<string, EntityCategoryKey> = {
    THREAT_ACTOR_HANDLE: "THREAT_ACTOR",
    BITCOIN_ADDRESS: "WALLET",
    ETHEREUM_ADDRESS: "WALLET",
    MONERO_ADDRESS: "WALLET",
    MALWARE_FAMILY: "MALWARE",
    RANSOMWARE_GROUP: "MALWARE",
    ORGANIZATION_NAME: "FORUM",
    ONION_URL: "ONION_URL",
    PASTE_URL: "PASTE_URL",
    EMAIL_ADDRESS: "EMAIL",
    PGP_KEY_BLOCK: "PGP_KEY",
    CVE: "CVE",
    CVE_NUMBER: "CVE",
    IP_ADDRESS: "C2_SERVER",
  };
  return m[entityType] ?? "OTHER";
}

/** Map graph `node.type` string (ThreatActor, …) to category / palette key. */
export function graphNodeTypeToCategory(nodeType: string): EntityCategoryKey {
  const m: Record<string, EntityCategoryKey> = {
    ThreatActor: "THREAT_ACTOR",
    CryptoWallet: "WALLET",
    MalwareFamily: "MALWARE",
    RansomwareGroup: "MALWARE",
    Forum: "FORUM",
    OnionURL: "ONION_URL",
    Paste: "PASTE_URL",
    EmailAddress: "EMAIL",
    PGPKey: "PGP_KEY",
    CVE: "CVE",
    C2Server: "C2_SERVER",
  };
  return m[nodeType] ?? "OTHER";
}

export const CATEGORY_ORDER: EntityCategoryKey[] = [
  "THREAT_ACTOR",
  "WALLET",
  "MALWARE",
  "FORUM",
  "C2_SERVER",
  "CVE",
  "PASTE_URL",
  "ONION_URL",
  "EMAIL",
  "PGP_KEY",
  "OTHER",
];

export const CATEGORY_META: Record<
  EntityCategoryKey,
  { label: string; short: string; icon: string; color: string }
> = {
  THREAT_ACTOR: { label: "Threat Actors", short: "Threat Actor", icon: "👤", color: "#e05c5c" },
  WALLET: { label: "Wallets", short: "Wallet", icon: "💰", color: "#9B9FEE" },
  MALWARE: { label: "Malware", short: "Malware", icon: "🦠", color: "#d08770" },
  FORUM: { label: "Forums", short: "Forum", icon: "💬", color: "#79b8ff" },
  C2_SERVER: { label: "C2 Servers", short: "C2 Server", icon: "🔌", color: "#b392f0" },
  CVE: { label: "CVEs", short: "CVE", icon: "🔓", color: "#f0e68c" },
  PASTE_URL: { label: "Pastes", short: "Paste", icon: "📋", color: "#56b6c2" },
  ONION_URL: { label: "Onion URLs", short: "Onion", icon: ".onion", color: "#9ecbff" },
  EMAIL: { label: "Emails", short: "Email", icon: "✉️", color: "#c9a35a" },
  PGP_KEY: { label: "PGP Keys", short: "PGP", icon: "🔐", color: "#73d397" },
  OTHER: { label: "Other", short: "Other", icon: "◆", color: "#6e7681" },
};

