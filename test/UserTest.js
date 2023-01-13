var EC = require('elliptic').ec;
const MixSC = artifacts.require("MixSC");//获取合约
const SDCTSystem = artifacts.require("SDCTSystem");
const UserConract = artifacts.require("User");
const BN = require("bn.js");
const { R1Verifier, SigmaVerifier, verifyProofEscrow } = require("../src/verifier");
const { createEscorw, User } = require("../src/user");
const { curve } = require("../src/params");
const { RequestRedeemInput } = require("../src/types");
const { assert } = require("elliptic/lib/elliptic/utils");

contract("MIXSC", async (accounts) => {
  let clients;
  let alice, bob;
  const N = 4;
  const INIT_BALANCE = 1000;
  const MIX_VALUE = 10;

  it("should deployed", async () => {
    const mixSC = await MixSC.deployed();
    const sdctSystem = await SDCTSystem.deployed();
    const userContract = await UserConract.deployed();
    clients = accounts.map((account) => new User(web3, mixSC, sdctSystem, userContract, account));
    alice = clients[0];
    bob = clients[1];
  });

  it("should print account", async () => {
    console.log(accounts);
    const gasPrice = await web3.eth.getGasPrice();
    console.log("gasPrice: ", gasPrice);
    var block = await web3.eth.getBlock("latest");
    console.log("gasLimit: ", block.gasLimit);
  });

  var pke = curve.g.mul(new BN(5));
  var pkr = curve.g.mul(new BN(3));

  
  // var k = new BN("2367");
  // var td = new BN("6434567876542342343");
  // var v = new BN(1);
  // var randomString = "helddddddlo";

  // var k = new BN("212367");
  // var td = new BN("6437876542342343");
  // var v = new BN(1);
  // var randomString = "apple";


  //***********************************核心测试**********************************************//
  // it("should escrow", async () => {
  //   var alice_balance = await web3.eth.getBalance(alice.account);
  //   var bob_balance = await web3.eth.getBalance(bob.account);

  //   console.log("转账前，alice用户余额：", alice_balance / 1e18, "ETH");
  //   console.log("转账前，bob用户余额：", bob_balance / 1e18, "ETH");

  //   var crEscParams = { k, td, v, randomString };
  //   let res = await alice.Escrow(pke, pkr, crEscParams);
  //   console.log("The time of escrow is:", res);

  //   //assert.isTrue(res);
  // });



  // it("should redeem", async () => {
  //   let redInput = { k, td, v, pkr, randomString };
  //   let res = await alice.Redeem(redInput, bob.account);
  //   console.log("The result of redeem is:", res);

  //   var alice_balance = await web3.eth.getBalance(alice.account);
  //   var bob_balance = await web3.eth.getBalance(bob.account);
  //   console.log("转账金额为1eth");
  //   console.log("转账后，alice用户余额：", alice_balance / 1e18, "ETH");
  //   console.log("转账后，bob用户余额：", bob_balance / 1e18, "ETH");

  //   //assert.isTrue(res);
  // });


  var times = 128; //调整测试的轮数
  var ks = generateNumBN(7);
  var tds = generateNumBN(8);
  var vs = generateVs();
  var randomStrings = generateStr(7);


  it("多次测试1", async () => {
    for (let i = 0; i < times; i++) {
      console.log("-----------------第", i + 1, "轮-----------------");
      var alice_balance = await web3.eth.getBalance(alice.account);
      var bob_balance = await web3.eth.getBalance(bob.account);

      console.log("第", i + 1, "轮", "转账前，alice用户余额：", alice_balance / 1e18, "ETH");
      console.log("第", i + 1, "轮", "转账前，bob用户余额：", bob_balance / 1e18, "ETH");
      let k, td, v, randomString;
      k = ks[i];
      td = tds[i];
      v = vs[i];
      randomString = randomStrings[i];

      var crEscParams = { k, td, v, randomString };
      let res1 = await alice.Escrow(pke, pkr, crEscParams);
      console.log("第", i + 1, "轮", "The result of escrow is:", res1);
      if (!res1) break;

      let redInput = { k, td, v, pkr, randomString };
      let res2 = await alice.Redeem(redInput, bob.account);
      console.log("第", i + 1, "轮", "The result of redeem is:", res2);

      var alice_balance = await web3.eth.getBalance(alice.account);
      var bob_balance = await web3.eth.getBalance(bob.account);
      console.log("第", i + 1, "轮", "转账金额为1eth");
      console.log("第", i + 1, "轮", "转账后，alice用户余额：", alice_balance / 1e18, "ETH");
      console.log("第", i + 1, "轮", "转账后，bob用户余额：", bob_balance / 1e18, "ETH");
    }
  });





  //*********************************************************************************//


  // var proof_format_test, aux_format_test, input_test;
  // it("should CreateRedeem", () => {
  //   let redInput = new RequestRedeemInput();
  //   redInput.k = k;
  //   redInput.td = td;
  //   redInput.v = v;
  //   redInput.pkr = pkr;
  //   redInput.randomString = randomString;
  //   startTime = Date.now();
  //   [proof_format_test, aux_format_test, input_test] = alice.CreateRedeem(redInput);
  //   endTime = Date.now();
  //   //console.log(proof_format, aux_format, input);
  //   console.log("The time of CreateRedeem:", endTime - startTime, "ms    ");
  // });

  // it("should VerifyRedeem", async () => {
  //   startTime = Date.now();
  //   let res = await alice.VerifyRedeem(proof_format_test, aux_format_test, input_test);
  //   endTime = Date.now();
  //   //console.log(proof_format, aux_format, input);
  //   console.log("The time of VerifyRedeem:", endTime - startTime, "ms    ");
  //   console.log("The result of VerifyRedeem is:", res);
  //   //assert.isTrue(res);
  // });





});






function generateStr(len) {

  let charStr = new String("qwertyuiopasdfghjklzxcvbnmjhgfdswertyiuytrehgfdsazxcvpasdfghjklzxcvbnmjhgfdswertyiuytrehgbnmnbvcxytrewlkjytregfdsnbvcqwe");

  res = []
  check = {}
  for (let j = 0; j < 500; j++) {
    _str = "";
    for (let i = 0; i < len; i++) {
      _str += charStr.charAt(Math.floor(Math.random() * charStr.length));
    }
    if (check[_str] != true) {
      check[_str] = true;
      res.push(_str);
    }
    if (res.length > 150) break;
  }
  return res;
}

function generateNumBN(len) {
  let numStr = new String("37643235768998765438756675564564243132134541233456789876567334693939272638496624891274269884232133699778977741444112236598987455");
  tmp = []
  check = {}
  for (let j = 0; j < 800; j++) {
    _str = "";
    for (let i = 0; i < len; i++) {
      _str += numStr.charAt(Math.floor(Math.random() * numStr.length));
    }
    if (check[_str] != true) {
      check[_str] = true;
      tmp.push(_str);
    }
    if (tmp.length > 150) break;
  }
  let res = [];
  for (let j = 0; j < tmp.length; j++) {
    res.push(new BN(tmp[j]));
  }
  return res;
}

function generateVs() {
  res = [];
  for (let i = 0; i < 200; i++) {
    res.push(new BN(1));
  }
  return res;
}
