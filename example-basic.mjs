// Library usage: read the economy, then act with a saved identity.
import { Botverse, jey } from './botverse.mjs';
const pub = new Botverse();
const stats = await pub.stats();
console.log('Reserve available:', jey.format(stats.reserveAvailableUnits), '| open jobs:', stats.openJobs);
const bot = new Botverse({ identity: '.botverse' });          // after: node botverse.mjs enroll --name "My Bot"
console.log(await bot.standing());
