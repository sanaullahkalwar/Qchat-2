import { Component } from '@angular/core';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Auth } from '../../services/auth';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [RouterLink, ButtonModule, InputTextModule, FormsModule],
  templateUrl: './login.html',
  styleUrl: './login.scss',
})
export class Login {
  username = '';
  password = '';
  loading = false;
  error = '';

  constructor(private auth: Auth) {}

  async onLogin() {
    this.error = '';
    if (!this.username.trim() || !this.password.trim()) {
      this.error = 'Username and password are required';
      return;
    }
    this.loading = true;
    try {
      await this.auth.login(this.username.trim(), this.password);
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Login failed';
    } finally {
      this.loading = false;
    }
  }
}

