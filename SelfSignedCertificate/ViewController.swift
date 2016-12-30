//
//  ViewController.swift
//  SelfSignedCertificate
//
//  Created by DongMeiliang on 26/12/2016.
//  Copyright © 2016 Meiliang Dong. All rights reserved.
//

import UIKit
import AFNetworking

class ViewController: UIViewController {

    // MARK: Properties
    let apiBaseURLString = "https://localhost/self-signed-certificate/"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.addSubview(afnetworkingButton)
        configureConstraintsForAFNetworkingButton()
        
        view.addSubview(sessionButton)
        configureConstraintsForSessionButton()
    }
    
    // MARK: Event Responder
    @objc func respondsToAFNetworking() {
        apiClient.get("self-signed-certificate/index.php", parameters: nil, progress: nil, success: { (sessionDataTask, responseObject) in
            print("\(sessionDataTask)\n\(responseObject)\n")

        }) { (sessionDataTask, error) in
            print("\(sessionDataTask)\n\(error)\n")
        }
    }
    
    var dataTask: URLSessionDataTask!
    
    @objc func respondsToSessionButton() {
        
        if let url = URL(string: "https://dongmeiliangsmacbook-pro.local/self-signed-certificate/index.php") {
            dataTask = defaultSession.dataTask(with: url)
            dataTask.resume()
        }
        else {
            print("instance url failed!")
        }
    }
    
    // MARK: Private Methods
    func configureConstraintsForAFNetworkingButton() -> Void {
        view.addConstraint(NSLayoutConstraint(item: afnetworkingButton, attribute: .centerX, relatedBy: .equal, toItem: view, attribute: .centerX, multiplier: 1.0, constant: 0))
        view.addConstraint(NSLayoutConstraint(item: afnetworkingButton, attribute: .top, relatedBy: .equal, toItem: topLayoutGuide, attribute: .bottom, multiplier: 1.0, constant: 20.0))
    }
    
    func configureConstraintsForSessionButton() -> Void {
        view.addConstraint(NSLayoutConstraint(item: sessionButton, attribute: .centerX, relatedBy: .equal, toItem: view, attribute: .centerX, multiplier: 1.0, constant: 0))
        view.addConstraint(NSLayoutConstraint(item: sessionButton, attribute: .top, relatedBy: .equal, toItem: afnetworkingButton, attribute: .bottom, multiplier: 1.0, constant: 20.0))
    }
    
    // MARK: Getters
    
    lazy var afnetworkingButton: UIButton = {
        let button = UIButton(type: .custom)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitleColor(.black, for: .normal)
        button.setTitle("AFNetworking", for: .normal)
        button.addTarget(self, action: #selector(respondsToAFNetworking), for: .touchUpInside)
        return button
    }()
    
    lazy var sessionButton: UIButton = {
        let button = UIButton(type: .custom)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitleColor(.black, for: .normal)
        button.setTitle("URLSession", for: .normal)
        button.addTarget(self, action: #selector(respondsToSessionButton), for: .touchUpInside)
        
        return button
    }()
    
    lazy var apiClient: AFHTTPSessionManager = {
        let client = AFHTTPSessionManager(baseURL: URL(string: "https://dongmeiliangsmacbook-pro.local/"))
        let selfSignedCertificates = AFSecurityPolicy.certificates(in: Bundle.init(for: ViewController.self))
        
        print("self signed certificates count: \(selfSignedCertificates.count)")
        client.securityPolicy = AFSecurityPolicy(pinningMode: .certificate, withPinnedCertificates: selfSignedCertificates)
        client.securityPolicy.allowInvalidCertificates = true
        
        return client
    }()
    
    lazy var defaultSession: URLSession = {
        let sessionConfiguration = URLSessionConfiguration.default
        
        let session = URLSession(configuration: sessionConfiguration, delegate: self, delegateQueue: OperationQueue.main)
        
        return session
    }()
}

extension ViewController: URLSessionDelegate, URLSessionTaskDelegate, URLSessionDataDelegate {
    
    // Fetching Data Using a Custom Delegate
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        print("did receive response:\(response)")
        
        completionHandler(.allow)
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        
        do {
            let responseObject = try JSONSerialization.jsonObject(with: data, options: .allowFragments)
            print("did receive \(responseObject)")

        } catch  {
            print("serialize to json failed: \(error)")
        }
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        print("did complete with \(error)")
    }
    
    // Authentication Challenges and TLS Chain Validation
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        print("authentication method \(challenge.protectionSpace.authenticationMethod)\n host: \(challenge.protectionSpace.host)")
        
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust && challenge.protectionSpace.host == "dongmeiliangsmacbook-pro.local" {
            
            // Custom evaluating a trust object
            let serverTrust = challenge.protectionSpace.serverTrust!
            let policy = SecPolicyCreateSSL(true, "dongmeiliangsmacbook-pro.local" as CFString)
            
            SecTrustSetPolicies(serverTrust, [policy] as CFArray)
            
            let path = Bundle.init(for: ViewController.self).path(forResource: "ServerCertificates", ofType: "cer")
            
            do {
                let certData = try NSData(contentsOfFile: path!, options: NSData.ReadingOptions(rawValue: 0))
                if let certificate = SecCertificateCreateWithData(nil, certData as CFData) {
                    SecTrustSetAnchorCertificates(serverTrust, [certificate] as CFArray)
                    
                    var allowConnection = false
                    
                    var trustResult: SecTrustResultType = .invalid
                    
                    let err = SecTrustEvaluate(serverTrust, &trustResult)
                    
                    if err == noErr {
                        allowConnection = (trustResult == .unspecified) || (trustResult == .proceed)
                    }
                    
                    print("err: \(err)\nallowConnection:\(allowConnection)")
                    
                    if allowConnection {
                        completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    }
                    else {
                        completionHandler(.cancelAuthenticationChallenge, nil)
                    }
                    
                }
                else {
                    print("certificate create with data failed")
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
                
            } catch  {
                print("read certificate data failed: \(error)")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            
        }
        else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

