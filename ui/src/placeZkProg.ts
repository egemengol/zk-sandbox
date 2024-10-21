import { SignedBytes88, ZkProgSign } from './zkProgSign';
import { SignerNoble } from './common';
import { Bytes } from 'o1js';

// export async function setupZkSign() {
//   const proofResult = document.querySelector<HTMLDivElement>('#proofResult')!;
//   // Compile the SecretNumberProgram
//   console.log('Start compiling ZkProgZign');
//   proofResult.innerHTML = 'Compiling';
//   await ZkProgSign.compile({ proofsEnabled: true });
//   console.log('Finish compiling ZkProgHash');
//   proofResult.innerHTML = '';

//   const payload = new Uint8Array(88);
//   payload[0] = 1;

//   const signer = new SignerNoble();
//   const signature = signer.sign(payload);

//   console.log('Generating proof');
//   proofResult.innerHTML = 'Generating Proof';
//   const pubInput = new SignedBytes88({
//     payload: Bytes.from(payload),
//     signature,
//   });
//   const proof = await ZkProgSign.verifySign(signer.pubO1, pubInput);
//   console.log('Generated proof');
//   proofResult.innerHTML = '';

//   console.log('Validating proof');
//   proofResult.innerHTML = 'Validating';
//   const result = await ZkProgSign.verify(proof);
//   if (result) {
//     console.log('Validated proof');
//     proofResult.innerHTML = 'Validated :)';
//   } else {
//     console.log('INVALID proof');
//     proofResult.innerHTML = 'Invalid';
//   }
// }

export async function zkWorker() {
  self.postMessage('compiling');
  await ZkProgSign.compile({ proofsEnabled: true });

  const payload = new Uint8Array(88);
  payload[0] = 1;
  const signer = new SignerNoble();
  const signature = signer.sign(payload);
  const pubInput = new SignedBytes88({
    payload: Bytes.from(payload),
    signature,
  });

  self.postMessage('proving');
  const proof = await ZkProgSign.verifySign(signer.pubO1, pubInput);

  self.postMessage('validating');
  const result = await ZkProgSign.verify(proof);
  if (result) {
    self.postMessage('valid :)');
  } else {
    self.postMessage('invalid');
  }
}

self.onmessage = async (e) => {
  if (e.data === 'start') {
    try {
      await zkWorker();
    } catch (error) {
      console.error('Error in zkWorker:', error);
      self.postMessage('Error occurred. Check console for details.');
    }
  } else if (e.data === 'ping') {
    self.postMessage('pong');
  }
};
