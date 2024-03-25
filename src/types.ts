export interface SopsJson extends Record<string, any> {
  sops: {
    age: {
      enc: string;
      recipient: string;
    }[];
    azure_kv?: any[];
    gcp_kms?: any[];
    hc_vault?: any[];
    kms?: any[];
    lastmodified: string;
    mac?: string;
    pgp?: any[];
    unencrypted_suffix?: string;
    version: string;
  };
}
