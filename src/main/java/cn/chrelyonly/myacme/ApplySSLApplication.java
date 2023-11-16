/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2015 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package cn.chrelyonly.myacme;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.Scanner;

/**
 *
 * @author chrelyonly
 */
@Slf4j
public class ApplySSLApplication {
    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // File name of the CSR
    private static final File DOMAIN_CSR_FILE = new File("domain.csr");

    // File name of the signed certificate
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");


    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 4096;

    private enum ChallengeType {HTTP, DNS}

    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *         Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
//        生成用户key
        KeyPair userKeyPair = loadOrCreateUserKeyPair();

        //创建Let's Encrypt会话
        // 使用“acme://letsencrypt.org”作为生产服务器
//        Session session = new Session("acme://letsencrypt.org/staging");
        Session session = new Session("acme://letsencrypt.org");

        //获取帐户。
        // 如果没有，创建一个新帐户。
        Account acct = findOrRegisterAccount(session, userKeyPair);
        //为域加载或创建密钥对。这不应该是userkeyPair!
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();

        //准备订购证书
        Order order = acct.newOrder().domains(domains).create();

//        执行所有必需的授权
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }

        // 订购证书
        order.execute(domainKeyPair);

        // 等待证书订购完成
        try {
//            重试次数
            int attempts = 5;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // 判断是否失败
                if (order.getStatus() == Status.INVALID) {
                    log.error("未找到记录: {}", order.getError()
                            .map(Problem::toString)
                            .orElse("unknown")
                    );
                    throw new AcmeException("订单失败了,放弃");
                }
                // 等待订单状态
                log.info("等待重试");
                Thread.sleep(5000L);
                order.update();
            }
        } catch (InterruptedException ex) {
            log.info("获取订单状态异常:{}",ex.getMessage());
            Thread.currentThread().interrupt();
        }

        // 获取证书
        Certificate certificate = order.getCertificate();

        log.info("证书{}已经生成!", domains);
        log.info("证书地址: {}", certificate.getLocation());
        log.info("证书地址: {}", DOMAIN_CHAIN_FILE);
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
        }
    }

    /**
     * 生成HTTP验证文件
     */
    private void loadOrCreateHTTPFile(String fileName, String content) {
            try (FileWriter fw = new FileWriter(fileName)) {
                fw.write(content);
                fw.close();
            }catch (Exception e){
                log.error("生成HTTP验证文件失败",e);
            }
    }
    /**
     * 生成用户key
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }

        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }

    }

    /**
     * Loads a domain key pair from {@link #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL of your new account with {@link Account#getLocation()} and store it somewhere.
     * If you need to get access to your account later, reconnect to it via {@link
     * Session#login(URL, KeyPair)} by using the stored location.
     *
     * @param session
     *         {@link Session} to bind with
     * @return {@link Account}
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // //要求用户接受服务条款，如果服务器提供给我们一个链接。
        Optional<URI> tos = session.getMetadata().getTermsOfService();
        tos.ifPresent(uri -> log.info("你需要阅读并同意服务条款: {}", uri));
        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        log.info("注册新用户, URL: {}", account.getLocation());

        return account;
    }

    /**
     * 授权域名。它将与您的帐户相关联，因此您将能够
     * 稍后检索域的签名证书。
     * @param auth
     *  {@link Authorization}
     */
    private void authorize(Authorization auth) throws AcmeException {
        log.info("授权域名 {}", auth.getIdentifier().getDomain());
        if (auth.getStatus() == Status.VALID) {
            return;
        }
//        选择验证方式
        log.info("请输入验证方式,1http,2dns,默认为1");
        Scanner scanner = new Scanner(System.in);
        String type = scanner.nextLine();
        ChallengeType challengeType;
        if ("2".equals(type)) {
            challengeType = ChallengeType.DNS;
        } else {
            challengeType = ChallengeType.HTTP;
        }
        Challenge challenge = switch (challengeType) {
            case HTTP -> httpChallenge(auth);
            case DNS -> dnsChallenge(auth);
        };
        if (challenge == null) {
            throw new AcmeException("没有验证方式");
        }else{
            log.info("验证方式:{}",challenge.getType());
        }
        // 已被验证则跳过
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        // 开始验证
        challenge.trigger();

        //轮询验证状态
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                if (challenge.getStatus() == Status.INVALID) {
                    log.error("未找到记录: {}", challenge.getError()
                            .map(Problem::toString)
                            .orElse("unknown"));
                }
                log.info("等待重试");
                Thread.sleep(5000L);

                // 更新状态
                challenge.update();
            }
        } catch (InterruptedException ex) {
            log.error("验证出现异常", ex);
            Thread.currentThread().interrupt();
        }

        // 超时
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("未通过验证 "
                    + auth.getIdentifier().getDomain() + ", ... 已结束.");
        }
        log.info("验证已结束.");
    }

    /**
     * http文件验证
     */
    public Challenge httpChallenge(Authorization auth) throws AcmeException {
        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new AcmeException("Found no " + Http01Challenge.TYPE
                        + " challenge, don't know what to do..."));

        // Output the challenge, wait for acknowledge...
        log.info("请在web服务器中创建一下目录与文件,并能够访问");
        log.info("我必须能够访问它: https://{}/.well-known/acme-challenge/{}",
                auth.getIdentifier().getDomain(), challenge.getToken());
        log.info("文件名: {}", challenge.getToken());
        log.info("文件内容: {}", challenge.getAuthorization());
        loadOrCreateHTTPFile(challenge.getToken(),challenge.getAuthorization());
        log.info("文件已保存至当前目录");
        log.info("准备好了就点击确认按钮");

        String message = "请在web服务器中创建一下目录与文件,并能够访问\n\n" +
                "https://" +
                auth.getIdentifier().getDomain() +
                "/.well-known/acme-challenge/" +
                challenge.getToken() +
                "\n\n" +
                "Content:\n\n" +
                challenge.getAuthorization();
        acceptChallenge(message);
        return challenge;
    }

    /**
     * dns验证
     */
    public Challenge dnsChallenge(Authorization auth) throws AcmeException {
        // Find a single dns-01 challenge
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)
                .map(Dns01Challenge.class::cast)
                .orElseThrow(() -> new AcmeException("Found no " + Dns01Challenge.TYPE
                        + " challenge, don't know what to do..."));

        // Output the challenge, wait for acknowledge...
        log.info("请在DNS服务器创建一个 TXT 类型的记录:");
        final String dnsName = Dns01Challenge.toRRName(auth.getIdentifier());
        final String dnsValue = challenge.getDigest();
        log.info("域名为: {} ,内容为 :{}",
                dnsName, dnsValue);
        loadOrCreateHTTPFile(dnsName +  ".txt", dnsValue);
        log.info("文件已保存至当前目录");
        log.info("如果准备好了就点击确认");
        String message = "请在DNS服务器创建一个 TXT 类型的记录:\n\n 域名为:" +
                dnsName +
                " 记录值: " +
                dnsValue;
        acceptChallenge(message);

        return challenge;
    }

    /**
     * 弹窗提示
     */
    public void acceptChallenge(String message) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                message,
                "请按照以下步骤操作",
                JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            throw new AcmeException("用户取消");
        }
    }

    public static void main(String... args) {
        if (args.length == 0) {
            System.err.println("请携带域名参数启动");
            System.exit(1);
        }
        log.info("启动中...");
        Security.addProvider(new BouncyCastleProvider());
        Collection<String> domains = Arrays.asList(args);
        System.out.println("domains = " + domains);
        try {
            ApplySSLApplication ct = new ApplySSLApplication();
            ct.fetchCertificate(domains);
        } catch (Exception ex) {
            log.error("获取域名证书失败 " + domains, ex);
        }
    }

}
