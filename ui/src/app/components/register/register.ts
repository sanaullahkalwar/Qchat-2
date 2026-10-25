import { Component } from '@angular/core';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Auth } from '../../services/auth';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [InputTextModule, ButtonModule, FormsModule, RouterLink],
  templateUrl: './register.html',
  styleUrl: './register.scss',
})
export class Register {
  firstName = '';
  lastName = '';
  username = '';
  password = '';
  confirmPassword = '';
  terms = false;
  loading = false;
  error = '';

  constructor(private auth: Auth) {}

  async onRegister() {
    this.error = '';
    if (!this.firstName.trim() || !this.lastName.trim() || !this.username.trim() || !this.password.trim()) {
      this.error = 'All fields are required.';
      return;
    }
    if (this.password !== this.confirmPassword) {
      this.error = 'Passwords do not match.';
      return;
    }
    if (!this.terms) {
      this.error = 'You must accept the Terms & Conditions.';
      return;
    }
    this.loading = true;
    try {
      await this.auth.register({
        firstName: this.firstName.trim(),
        lastName: this.lastName.trim(),
        username: this.username.trim(),
        password: this.password,
      });
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Registration failed.';
    } finally {
      this.loading = false;
    }
  }
}

