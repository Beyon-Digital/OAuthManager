export interface TokenStorage {
    get(id: string): string | null;
    set(id: string, value: string): void;
    remove(id: string): void;
}

export class Storage implements TokenStorage {
    get(id: string): string | null {
        return localStorage.getItem(id);
    }

    set(id: string, value: string): void {
        localStorage.setItem(id, value);
    }

    remove(id: string): void {
        localStorage.removeItem(id);
    }

}

export const storage = new Storage();
