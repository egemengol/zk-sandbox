import './style.css';
// import { setupZkSign } from './placeZkProg';

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div>
    <h2>ZK Program Sandbox</h2>
    <div id="proofFormContainer"></div>
    <div id="proofResult"></div>
  </div>
`;

async function main() {
  const proofResult = document.querySelector<HTMLDivElement>('#proofResult')!;
  const worker = new Worker(new URL('./placeZkProg.ts', import.meta.url), {
    type: 'module',
  });
  worker.onmessage = (e) => {
    const msg = e.data as string;
    console.log(msg);
    proofResult.innerHTML = msg;
  };
  worker.postMessage('start');
}

(async () => {
  await main();
})();
