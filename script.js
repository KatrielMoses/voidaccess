const copyButton = document.querySelector('[data-copy]');
if (copyButton) {
  copyButton.addEventListener('click', async () => {
    const value = copyButton.dataset.copy;
    try {
      await navigator.clipboard.writeText(value);
      const label = copyButton.querySelector('.copy-label');
      label.textContent = 'Copied';
      copyButton.setAttribute('aria-label', 'Install command copied');
      setTimeout(() => { label.textContent = 'Copy'; }, 1800);
    } catch {
      copyButton.querySelector('.copy-label').textContent = 'Select';
    }
  });
}
