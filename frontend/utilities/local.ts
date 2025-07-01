const {
  window: { localStorage },
} = global;

const local = {
  clear: (): void => {
    localStorage.clear();
  },
  getItem: (itemName: string): string | null => {
    return localStorage.getItem(`MOBIUS::${itemName}`);
  },
  setItem: (itemName: string, value: string): void => {
    return localStorage.setItem(`MOBIUS::${itemName}`, value);
  },
  removeItem: (itemName: string): void => {
    localStorage.removeItem(`MOBIUS::${itemName}`);
  },
};

export const authToken = (): string | null => {
  return local.getItem("auth_token");
};

export const clearToken = (): void => {
  return local.removeItem("auth_token");
};

export default local;
