import { useEffect, useState } from 'react';

// Object URLs pin their Blob in memory until revoked. Creating one during render leaks a copy of the
// content on every re-render (and gives an <iframe> a new src, reloading it), so these helpers
// create one URL per piece of data and revoke it when the data changes or the component unmounts.

/**
 * Object URL for `data` (ArrayBuffer/typed array/Blob part), stable while `data` and `type` are.
 * @param {BlobPart | null | undefined} data
 * @param {string} [type]
 * @returns {string | null}
 */
export const useObjectUrl = (data, type) => {
  const [url, setUrl] = useState(/** @type {string | null} */ (null));
  useEffect(() => {
    if (data === null || data === undefined) {
      setUrl(null); // eslint-disable-line react-hooks/set-state-in-effect -- the URL is an external resource created and revoked here
      return undefined;
    }
    const next = URL.createObjectURL(new Blob([data], type ? { type } : undefined));
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [data, type]);
  return url;
};

/** @param {{ data: BlobPart, type?: string, title: string, className?: string }} props */
export const BlobFrame = ({ data, type, title, className = '' }) => {
  const url = useObjectUrl(data, type);
  return url ? <iframe title={title} src={url} className={className} /> : null;
};

/** @param {{ data: BlobPart, type?: string, alt: string, className?: string }} props */
export const BlobImage = ({ data, type, alt, className = '' }) => {
  const url = useObjectUrl(data, type);
  return url ? <img src={url} alt={alt} className={className} /> : null;
};

/**
 * Save `blob` as a file via a temporary link, releasing the object URL afterwards.
 * @param {Blob} blob
 * @param {string} fileName
 */
export const downloadBlob = (blob, fileName) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // The download has started from the click; give the browser a moment before releasing the blob
  setTimeout(() => URL.revokeObjectURL(url), 10000);
};
