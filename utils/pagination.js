export const parsePagination = (query = {}, { defaultLimit = 25, maxLimit = 100 } = {}) => {
  const page = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const limit = Math.min(maxLimit, Math.max(1, Number.parseInt(query.limit, 10) || defaultLimit));
  return { page, limit, offset: (page - 1) * limit };
};

/** Build pagination metadata plus pre-rendered links that preserve the active filters. */
export const buildPagination = ({ page, limit, total, query = {}, basePath = '' }) => {
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const linkFor = (p) => {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => {
      if (k === 'page' || v === undefined || v === null || v === '') return;
      (Array.isArray(v) ? v : [v]).forEach((item) => params.append(k, item));
    });
    params.set('page', String(p));
    return `${basePath}?${params.toString()}`;
  };
  const windowStart = Math.max(1, page - 2);
  const windowEnd = Math.min(totalPages, page + 2);
  const pages = [];
  for (let p = windowStart; p <= windowEnd; p += 1) pages.push({ number: p, url: linkFor(p), active: p === page });
  return {
    page, limit, total, totalPages,
    from: total === 0 ? 0 : (page - 1) * limit + 1,
    to: Math.min(total, page * limit),
    hasPrev: page > 1, hasNext: page < totalPages,
    prevUrl: page > 1 ? linkFor(page - 1) : null,
    nextUrl: page < totalPages ? linkFor(page + 1) : null,
    pages
  };
};
