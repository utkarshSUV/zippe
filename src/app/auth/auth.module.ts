import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { NgxAuthRoutingModule } from './auth-routing.module';
import { NbAuthModule } from '@nebular/auth';
import { NbEvaIconsModule } from '@nebular/eva-icons';
import { 
  NbAlertModule,
  NbButtonModule,
  NbCheckboxModule,
  NbInputModule
} from '@nebular/theme';
import { NgxLoginComponent } from './login/login.component';
import { NgxRegisterComponent} from './register/register.component';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    RouterModule,
    NbAlertModule,
    NbInputModule,
    NbButtonModule,
    NbCheckboxModule,
    NgxAuthRoutingModule,
    NbAuthModule,
    NbEvaIconsModule,
  ],
  declarations: [
    NgxLoginComponent,
    NgxRegisterComponent
  ],
})
export class NgxAuthModule { }
