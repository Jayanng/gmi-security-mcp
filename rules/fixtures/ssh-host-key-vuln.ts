import { Client } from "ssh2";

class SSHConnectionManager {
  private async buildClientConfig(key: string, config: any) {
    const sshConfig: any = {
      host: config.host,
      port: config.port,
      username: config.username,
      readyTimeout: 30000,
      password: config.password,
    };
    return sshConfig;
  }
}
