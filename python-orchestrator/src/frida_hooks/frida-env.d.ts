declare const Java: any;
declare function send(message: any, data?: any): void;
declare function recv(type: string, callback: (message: any, data: any) => void): void;
declare function recv(callback: (message: any, data: any) => void): void;
declare const rpc: any;
