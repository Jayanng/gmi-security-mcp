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
    sshConfig.hostVerifier = await this.createHostVerifier(key, config);
    return sshConfig;
  }

  private async connectOnce(key: string, config: any) {
    const client = new Client();
    const sshConfig = await this.buildClientConfig(key, config);
    client.connect(sshConfig);
  }
}
