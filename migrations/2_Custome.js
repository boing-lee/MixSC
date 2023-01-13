var SDCTSetup = artifacts.require("SDCTSetup");
var SDCTVerifier = artifacts.require("SDCTVerifier");
var TokenConverter = artifacts.require("TokenConverter");
var SDCTSystem = artifacts.require("SDCTSystem");
var MixSC = artifacts.require("MixSC");
var User = artifacts.require("User");
var Primitives = artifacts.require("Primitives");
var BN128 = artifacts.require("BN128");

module.exports = function(deployer) {
    // 任务就是 部署合约
    
    deployer.deploy(SDCTSetup).then
    (function() {
        return deployer.deploy(SDCTVerifier, SDCTSetup.address);
    }).then(function(){
        return deployer.deploy(TokenConverter);
    }).then(function(){
        return deployer.deploy(BN128);
    }).then(function() {
        return  deployer.deploy(SDCTSystem, SDCTSetup.address, SDCTVerifier.address, TokenConverter.address);
    }).then(function(){
        return deployer.deploy(Primitives);
    }).then(function() {
        
        deployer.link(Primitives, MixSC);
        return deployer.deploy(MixSC, SDCTSystem.address, SDCTSetup.address);
    }).then(function(){
        deployer.link(Primitives, User);
        return deployer.deploy(User, SDCTSetup.address, MixSC.address);
    });
};
