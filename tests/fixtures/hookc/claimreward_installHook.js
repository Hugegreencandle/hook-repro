const xahau = require('xahau');

const seed = 'sYourSeedHere'; // Replace with your actual seed, get one at https://xahau-test.net/
const network = "wss://xahau-test.net";

async function installHook() {
  const client = new xahau.Client(network);
  const wallet = xahau.Wallet.fromSecret(seed);
  console.log(`Account: ${wallet.address}`);

  try {
    await client.connect();
    console.log('Connected to Xahau');

    const prepared = {
      "TransactionType": "SetHook",
      "Account": wallet.address,
      "Hooks": [
        {
          "Hook": {
            "HookHash": "805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA",
            "HookNamespace": "0000000000000000000000000000000000000000000000000000000000000000",
            "HookOn": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFBFFFFF",
            "HookCanEmit": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFFFFFFFFFFFFFFFBFFFFF", // Can emit ClaimReward
            "Flags": 4
          }
        }
      ],
    };

    console.log("Prepared SetHook transaction:", JSON.stringify(prepared, null, 2));

    const tx = await client.submit(prepared, { wallet });
    console.log("Transaction result:", JSON.stringify(tx, null, 2));

  } catch (error) {
    console.error('Error:', error);
  } finally {
    await client.disconnect();
    console.log('Disconnected from Xahau');
  }
}

installHook();
