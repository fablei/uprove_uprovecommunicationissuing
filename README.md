# U-Prove Communication
Please note that this repository is a result of the Master Thesis of the author at the BFH [8]. Newcomer and interested programmers, pls see the "Contributing" chapter as well.

This library was build to make the communication between the U-Prove actors (Issuer, Prover and Verifier) - from the U-Prove Cryptographic Specification V1.1 Revision 3 [1] - more convenient and standardize. Further is it feasible to initialize an existing Issuer and start - by creating the first message - the communication protocol with the Prover. Additionally the communication gets logged.

## Getting Started
Get yourself a local copy of this repository and open the solution file (uprove_uprovecommunication.sln) in a Visual Studio 2015 (or a more recent version).

### Prerequisites
Before building the project, install the following dependencies:
* 	UProveCrypto [2] (Apache License Version 2.0)
* 	U-Prove Extensions [3] (Microsoft Research License Terms)
* 	U-Prove JSON [4] (MIT license)
* 	Log4Net [5] (Apache License Version 2.0)

### Installing
* 	UProveCrypto, U-Prove Extensions and U-Prove JSON  
	You need to download and build the uprove-extension-csharp-sdk_fork [2], uprove-extension-csharp-sdk [3] or uprove_json [4] and include the build dependencies in the project.
* 	Log4Net  
	Open the Paket-Manager-Console and execute the following command (for further details, pls visit the official project webpage [7])
	```
	PM> Install-Package log4net
	```

### Usage
There are three main classes (IssuingIssuer, IssuingProver and IssuingVerifier) which has there own scope (as the name already tells). 

#### Token generation
This section describes how Issuer and Prover could generate one or more tokens together. For a better over view some variables may have a short description.
* 	attributeWithKey contains attributes received e.g. from an AP (e.g. new BasicClaim() { name = "surname", values = new List<string>() { "Mustermann" }, qualitylevel = "loa2" })
* 	rangeProofAttributes contains a list of attribute names which could be used for performing a range proof
* 	supportedDateAttributes contains a list of attribute names which represents attribute values with the type date 

```cs
	IssuingIssuer ii = new IssuingIssuer(jsonIssuerParameters, privateKeyForThisIssuer);
	ii.Init(attributeWithKey, rangeProofAttributes, supportedDateAttributes);
	
	string firstMessageJson = ii.GenerateFirstMessage(numberOfTokens, ti, devicePublicKey);
	
	// send firstMessageJson + attributes included into the first message to the prover
	
	IssuingProver isp = new IssuingProver();
	isp.Init(firstMessageJson, pi, attributeWithKey, numberOfTokens, ti, jsonIssuerParameters, supportedDateAttributes);
	string secondMessageJson = isp.GenerateSecondMessage(devicePublicKey);
	
	// send secondMessageJson back to the issuer
	
	string thirdMessageJson = ii.GenerateThirdMessage(secondMessageJson);
	
	// send thirdMessageJson to the prover - work by the issuer is done by now
	
	isp.GenerateTokens(thirdMessageJson);
	UProveKeyAndToken[] ukats = isp.KeyAndToken;	
```

#### Proof generation
This section is made for Provers. In it, there is described how the different proofs could be made. Prerequisite is a generated and valid token.

* 	proofRequirements contains the requirements for all proofs, e.g. which attribute value should be disclosed and which committed, as well as the message
* 	verifiersMembers contains a list of VerifierMembers, which includes the attribute name of the attribute - used for the proof - as well as the members - defined by the Verifier and the proof index of the proof used from the Verifiers publication

```cs
	ProverProof pp = new ProverProof();
	string proofJson = pp.Init(isp.IP, attributeWithKey, proofRequirements, ukats[0], supportedDateAttributes, devicePresentationContext);
	List<string> setMembershipProofJsons = pp.GenerateSetMembershipProofs(new int[] { commitmentIndexForSetMembershipProof }, verifiersMembers);

	// the setMembershipProofJsons contains a list of setMembershipProofs
```


#### Token and Proofs validation
This section describes how the Prover could present the created tokens with some proofs to the Verifier and how the verification is done.

* 	trustedIssuersJson a json which contains a set of trusted issuer parameter - defined by the Verifier itself
* 	verifiersMembers contains a list of VerifierMembers, which includes the attribute name of the attribute - used for the proof - as well as the members - defined by the Verifier and the proof index of the proof used from the Verifiers publication

```cs
	IssuingVerifier isv = new IssuingVerifier();
	isv.Init(jsonIssuerParameter, proofJson, jsonTokenFromProver, trustedIssuersJson);
	
	bool isSetMembershipProof = isv.VerifySetMembershipProofs(setMembershipProofJsons, verifiersMembers);
```
	
## Running the tests
In the "Test" menu of Visual Studio, select the "All Tests" from the "Run" submenu item. Note that a complete test run takes some time to complete. If you want to extend the tests, feel free to edit the "uprove_uprovecommunicationissuing_tests" project in the Visual Studio. The whole communication gets tested step by step and has dependencies to the previous message generation.

## Contributing
Contributors are always welcome. As information about U-Prove is only spread found the official webpage from Microsoft, I would like to build up a little community which is working with U-Prove and helps newcomer to get in touch easily. To do so, it would be nice if you could open a new "issue" at this [page](https://github.com/fablei/uprove_samlcommunication/issues) and select as kind -> task and fill in your project link.

If you're brand-new to the project and run into any blockers or problems, please open an [issue on this repository](https://github.com/fablei/uprove_samlcommunication/issues) and I would love to help you fix it for you!


## Author
* 	Bojan Leimer


## References

[1] https://www.microsoft.com/en-us/research/publication/u-prove-cryptographic-specification-v1-1-revision-3/

[2] https://github.com/fablei/uprove-csharp-sdk

[3] https://github.com/fablei/uprove-extension-csharp-sdk or https://www.microsoft.com/en-us/research/publication/u-prove-extensions/

[4] https://github.com/fablei/uprove_json

[5] https://logging.apache.org/log4net/

[6] https://www.ti.bfh.ch/de/master/msc_engineering.html