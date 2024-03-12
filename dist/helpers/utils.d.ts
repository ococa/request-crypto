import { randomPassType } from '../types';
import { AxiosRequestHeaders, AxiosResponseHeaders } from 'axios';
/**
 * 获取随机数
 * @param {number} len 随机数长度
 * @param {string} mode 随机数模式 high:高级 medium:中等 low:低等
 */
export declare const randomPassword: randomPassType;
export declare const HEADER_ENCRYPT_KEY = "X-Encrypt-Key";
export declare const HEADER_ENCRYPT_WITH = "X-Encrypt-With";
export declare const setRequestCryptoHeader: (headers: AxiosRequestHeaders, encryptKey: string) => AxiosRequestHeaders;
export declare const isEncryptResponse: (headers: AxiosResponseHeaders) => boolean | "" | 0 | null;
export declare function ab2str(buf: ArrayBuffer, encoding?: string): string;
export declare function transformResponseData(data: unknown): unknown;
export declare function transformArrayBufferToJsonData(data: ArrayBuffer): any;
export declare function transformStringToJsonData(data: string): any;
/**
 *  正则判断 排除下列字符串开头
 *  /api/logmanage
 *  /api/data-source
 *  /api/enterpriseadmin
 *  /api/componentmanager
 *  /api/spacemanager
 *  /api/filemanager
 *
 *  不加密
 *  /bi-api/api
 */
export declare const isEncryptListApi: (url: string) => boolean;
export declare const encryptWhiteList: (url: string) => boolean;
export declare const shouldEncrypt: (url: string) => boolean;
