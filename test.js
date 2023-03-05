const hmac = require(".");
const crypto = require("crypto");

const key = Buffer.from("Hello");
const message = Buffer.from("World!");

process.stdout.write("Sync test...");
const toCheck = hmac.hmacSync(message, key, function(content){
    const syncTest = crypto.createHash("sha256");
    syncTest.update(content);
    return syncTest.digest();
}, 64);
const hmac1 = crypto.createHmac("sha256", key);
hmac1.update(message);
const toCompare = hmac1.digest();

function compare(buffer1, buffer2){
    const length = Math.max(buffer1.length, buffer2.length);
    for(let i=0;i<length;i++){
        const val1 = buffer1[i] || 0;
        const val2 = buffer2[i] || 0;
        if(val1 !== val2) return false;
    }
    return true;
}

if(compare(toCheck, toCompare)){
    console.log(" Test passed!");
}else{
    console.error(" Not passed!");
    process.exit(1);
}

const hmac2 = crypto.createHmac("sha256", key);
hmac2.update(message);
const toCompare2 = hmac2.digest();

process.stdout.write("Async test...");
hmac.hmac(message, key, function(content){
    return new Promise(r => {
        const syncTest = crypto.createHash("sha256");
        syncTest.update(content);
        const digest = syncTest.digest();
        setTimeout(() => {
            r(digest);
        }, 500);
    });
}, 64).then(toCheck2 => {
    if(compare(toCheck2, toCompare2)){
        console.log(" Test passed!");
    }else{
        console.error(" Not passed!");
        process.exit(1);
    }
});