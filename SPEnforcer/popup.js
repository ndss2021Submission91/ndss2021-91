document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({currentWindow: true, active: true}, function (tabs) {
    if (tabs.length) {
      let tab = tabs[0];
      let url = tab['url'];
      if (url !== undefined) {
        chrome.runtime.sendMessage({action: "isSPenabled", url: url}, function (response) {
          window.spenabled.innerText = response.text;
          window.sitepolicy.innerText = response.sp;
          window.site.value = response.site;

        });
      }
    }
  });

  window.button.onclick = function () {
    let site = window.site.value;
    let policy = window.sitepolicy.value;
    chrome.runtime.sendMessage({action: "setSP", site: site, policy: policy}, function (response) {
      window.spset.innerText = response;
    });
  }
});
