import './style.css';
import { setupZkSign } from './placeZkProg';

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div>
    <h2>ZK Program Sandbox</h2>
    <div id="proofFormContainer"></div>
    <div id="proofResult"></div>
  </div>
`;

(async () => {
  await setupZkSign();
})();
