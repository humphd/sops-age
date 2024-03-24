export interface GreetOptions {
  logger?: (message: string) => void;
  message: string;
  times?: number;
}

export interface SopsJson extends Record<string, any> {
  sops: {
    age: { enc: string; recipient: string }[];
  };
}
